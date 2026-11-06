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

## Reserved names

`guard_token` (a form field) and `X-Guard-Token` (a header) carry the CAPTCHA token; the guard removes the field from every
request before the endpoint sees it, so an endpoint must not use a parameter of that name.
