# frappe_guard

CAPTCHA and rate limit for the public forms and the sign-up/login endpoints of Frappe v15 sites.

Status: under construction (0.1.0, nothing is released). The plan, the decisions and the work packages are in
`docs/guard/plan.md` of the infrastructure repository `tasmail/erpnext-infra` (pull request #329).

## What it will do (planned, none of it is built yet)

- Checks a CAPTCHA token (reCAPTCHA v3 first, Cloudflare Turnstile later) on guest forms and on `sign_up`,
  `reset_password`, `send_login_link` and `login`.
- Limits the rate of those actions with atomic Redis counters (per IP, account and recipient) behind a trusted proxy chain.
- Runs per action in the modes `off`, `monitor` (verify and log, never block) and `enforce`.
- One `before_request`/`auth_hooks` choke point; no whitelisted method is overridden.

## Install

```
bench get-app https://github.com/tasmail/frappe-guard
bench --site <site> install-app frappe_guard
```

Keys and modes are per site, in the site config (`guard_recaptcha_site_key`, `guard_recaptcha_secret`, `guard_hosts`)
and the Single DocType `Guard Settings`. A secret is never stored in the database or logged.

## Development

Python 3.10+, Frappe v15. Tabs, line length 110: `ruff check . && ruff format --check .`. The unit tests run without
a bench (`pytest`); the integration tests need a site and Redis. See `AGENTS.md` for the rules of work.

## Licence

MIT. The idea of the modes and the fail policy comes from reviewing `frappe-contact-form`; no code of it is copied.

## Browser side

`frappe_guard/public/js/guard.js` (served as `/assets/frappe_guard/js/guard.js`, or inlined in the head of a page) makes the token:

```js
FrappeGuard.init({ siteKey: "<the public site key>" });
const response = await FrappeGuard.request("/api/method/<method>", { action: "contact", method: "POST", body: formData });
```

The provider script loads on the first interaction with a form matching `form[data-guard-action]` (not at page load), from
`www.google.com`, else `www.recaptcha.net`. One token is made per request. The request asks for JSON (`Accept`,
`X-Requested-With`): Frappe answers any other client with an HTML page on a refusal. A failure of the browser side is never
thrown: the request goes without a token and the server decides. The site key is put in the page; do not fetch it.

Notes:
- `request` merges its headers with the ones of the caller (a `Headers` object, pairs or a plain object; case-insensitive) and does
  not set `credentials` or a content type (a `FormData` body gets its own). The caller passes `X-Frappe-CSRF-Token` where it needs one.
- The whole token step is capped at 8 seconds; after the provider could not be reached, requests do not wait for it again for
  15 seconds. A request that cannot get a token goes out without it.
- It needs `Promise` and `fetch` (no polyfill). `init({hosts})` accepts plain host names only. Load one `api.js?render=` per
  page: another key on the same page makes `execute` fail.
- Content Security Policy: `script-src` and `frame-src` need `www.google.com`, `www.recaptcha.net` and `www.gstatic.com`. The
  reCAPTCHA badge may be hidden only together with the disclosure text. A form inside a shadow root does not trigger the early
  load (the script then loads when the first request asks for a token).
- A cross-origin use needs `X-Guard-Token` and `X-Requested-With` in the `Access-Control-Allow-Headers` of the server.

## Rate limit

Counters per action in the cache Redis (`SET NX EX` + `INCR` in one transaction, keys with the db-name prefix and a keyed hash of
the identity). Kinds: `ip` (the N-th entry from the right of `X-Forwarded-For`, `guard_trusted_hops`, default 1; an unknown client
is not counted), `account`, `recipient` (the address a mail goes to) and `site` (every request of the action). A soft limit raises
the score the CAPTCHA demands, a hard limit refuses. The `account` and `recipient` counters of a guest are counted after the CAPTCHA
passed, so a request without a valid token cannot burn the counter of a victim's address; a request refused by a per-identity limit
is not counted against the shared counters. `guard_limits` of the site config tunes them per action and kind.
`guard_trusted_hops` has **no default**: until the platform writes the verified proxy chain to the site config every client is
*unknown*: not counted per client (a bucket of the proxy address would lock everyone out), the requests of unknown clients are
counted per action (never refused) and a loud log line is written once per process. `account` and `recipient` have soft = hard (they are counted after the CAPTCHA, so there is no score left to raise). Known residual risk: an attacker
with valid tokens can use up the recipient cap (20 an hour) of a victim's address and so block his password reset for the hour;
no counter fixes that, the cap bounds the mail bomb instead. Notes: the cache Redis normally runs with `maxmemory` and an eviction policy, so a counter can reset under memory pressure; a hung
Redis is not timed out by Frappe (`from_url` sets no socket timeout). Verify the proxy chain before using `enforce`.

## Reserved names

`guard_token` (a form field) and `X-Guard-Token` (a header) carry the CAPTCHA token; the guard removes the field from every
request before the endpoint sees it, so an endpoint must not use a parameter of that name.
