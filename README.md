# frappe_guard

CAPTCHA and rate limit for the public forms and the guest endpoints of Frappe v15 sites (contact forms, sign-up, password reset,
e-mail login link, downloads).

Status: **under construction, nothing is released.** Merged: the skeleton, the check core and the request hook (P1 to P3). In
review: the rate limiter (PR #4) and the browser script (PR #5). Not built yet: the password `login` (it needs its own mechanism,
see below), the Press side that installs it and writes the keys, and the migration of the code that lives in `fossdoc_shop`.
The plan, the decisions and the work packages are in `docs/guard/plan.md` of the infrastructure repository `tasmail/erpnext-infra`.

## Why

The public endpoints of a Frappe site are open to anyone, and bots use them for two things:

- **Mail abuse.** `sign_up`, `reset_password` and `send_login_link` send an e-mail to an address chosen by the caller: an attacker
  makes the site mail a victim thousands of times (and burns the reputation of the sending domain). A contact form is spammed the
  same way, and every acknowledgement is a mail to a stranger.
- **Cost and spam.** Forms that start work for a stranger (a calculation, a download link) are called in bulk.

Frappe's own protection does not cover this: the limit of `@rate_limit` is keyed on `frappe.local.request_ip`, which is the
left-most entry of `X-Forwarded-For` and is chosen by the client (change the header, change the bucket); `sign_up` has no limit
but 300 new users an hour for the whole site; the limit at the edge (nginx) sees only the path, not a `cmd` in a request body.
Before this app each of our sites had its own copy of a CAPTCHA check (the shop code of FossDoc), with no counters.

## How it works

One hook, `auth_hooks` (`hook.guard_request`), looks at **every** request of the site before Frappe dispatches it:

```
request -> not OPTIONS? -> which method is it? -> is that method guarded? -> mode off? -> stop
                                                                     |
   counters that need no token (address, site)  ---- over the hard limit: refuse (417)
                    |
   signed in? ---- yes: no CAPTCHA, but the account and recipient counters also run
                    |  no
   CAPTCHA token (header X-Guard-Token or field guard_token) -> verified by Google reCAPTCHA v3
                    |  passed
   counters of the recipient (the address a mail goes to) ---- over the hard limit: refuse (417)
                    |
   Frappe runs the endpoint
```

`auth_hooks` runs after the API key and bearer check and before the dispatch, and it runs for every request, so the guard is
**one choke point** and does not override any whitelisted method (it cannot collide with the overrides of other apps and survives a
change of the signature of a stock function).

**Which method is a request?** Exactly as Frappe decides it, because a guard that reads it differently can be bypassed:
- `cmd` in the query string, the form or a JSON body wins on **any** path and with any HTTP method (Frappe dispatches
  `elif frappe.form_dict.cmd` before it looks at `/api/`); the stock login page and the pages of Frappe post `cmd` to `/` or `/login`.
- With no `cmd`, a path under `/api/` is matched with Frappe's own router (`frappe.api.API_URL_MAP`): `/api/method/<m>`,
  `/api/v1/method/<m>`, `/api/v2/method/<m>` and `/api/v2/method/<doctype>/<m>`, with or without a trailing slash and with a suffix
  after the method name (Frappe runs `<m>` for `/api/method/<m>/anything`). The endpoint is recognised by identity, not by name.
- `upload_file` is open to guests and calls the method named in its `method` field, also under any alias
  (`frappe.api.v2.upload_file`, a re-export by a site app): the named method is the requested one.
- The name is matched as requested, before `override_whitelisted_methods`.

**Why a signed-in user is not asked for a CAPTCHA** (any session that is not Guest, also an API key or a bearer token): the
CAPTCHA tells a bot from a person, and the counters (account, recipient, address, site) still apply, because a self-registered
account can abuse `sign_up` and the mail actions too.

## Which endpoints it closes

The map `method -> action` is data (the code holds defaults for the stock endpoints; a site adds its own in `guard_action_map`).

| Action | Endpoint (default map) | Why | When the provider is down | Counters besides the address and the site |
| --- | --- | --- | --- | --- |
| `sign_up` | `frappe.core.doctype.user.user.sign_up` | creates an account and mails the address in `email` | refuse (fail closed) | recipient (`email`), account |
| `reset_password` | `frappe.core.doctype.user.user.reset_password` | mails the user in `user` | pass (fail open) | recipient (`user`), account |
| `send_login_link` | `frappe.www.login.send_login_link` | mails a login link to `email` | pass (fail open) | recipient (`email`), account |
| `contact` | `frappe.www.contact.send_message` | sends a message to the company and acknowledges to the sender | refuse | |
| `download` | `fossdoc_shop.downloads.request_download` | mails download links of the FossDoc demo | refuse | |
| `calculation` | `fossdoc_shop.api.send_calculation` | mails the calculation of the FossDoc shop | refuse | |

*Fail open* for login, reset and the link is deliberate: a Google outage must not lock customers out of their accounts; the
counters still bound the abuse. The forms and sign-up *fail closed* with a message that asks to try again later.

**What it does not close.** The password `login` (`cmd=login`, `/api/method/login`) is processed by Frappe's `LoginManager`
inside `HTTPRequest()`, **before any hook**, so this hook cannot see it; it needs its own mechanism (package P7: a wrapper of
`LoginManager.login`, or password login switched off where a shop uses only the e-mail link). Not in scope: the OTP login of
the staff, a WAF, and the edge limit of the proxy (which stays and is extended on the Press side).

## Modes

Every action has a mode: `off` (nothing is checked or counted), `monitor` (checked, counted and logged, **never refused**) or
`enforce` (a failed check or a hard limit is refused with a validation error, HTTP 417). Every site starts in `monitor` for at
least a week; `enforce` is switched per action in the site config, without a deploy. A mistyped override is ignored **and logged by
field name**, never silently.

## Configuration

Keys and host lists are per site and live in the **site config** (written by the platform, never in the database); the tunables
that carry no secret are in the Single DocType `Guard Settings` (`default_mode`, `action_overrides`). The site config wins.

| Site config key | Meaning |
| --- | --- |
| `guard_recaptcha_site_key`, `guard_recaptcha_secret` | the reCAPTCHA v3 key pair of the site (the secret is never logged) |
| `guard_hosts` | the host names the tokens are accepted from (public, internal and staging names); a token of another host is refused; one list per key |
| `guard_mode` | the default mode of every action (`off`, `monitor`, `enforce`) |
| `guard_actions` | `{action or "*": {"mode", "threshold", "fail", "provider_action"}}` |
| `guard_action_map` | `{"dotted.method": "action"}`: the endpoints of a site |
| `guard_limits` | `{action: [{"kind", "window", "soft", "hard"}]}`: the counters, replaced per kind |
| `guard_trusted_hops`, `guard_ip_header` | the number of trusted proxies and the header that carries the client address |

A site without a secret or host list is *not configured*: it refuses the guarded actions in `enforce` (and passes them in
`monitor`, in developer mode and in tests), so a missing key never opens a form silently.

## Why it is built this way

- **reCAPTCHA v3 first**: no new account, no visible challenge. The score is compared with a threshold **per action**; a score of
  0 is honoured; the host in Google's reply must be in `guard_hosts`; `remoteip` is not sent (behind a proxy it is the proxy);
  the action in the reply must be the expected one. A token is single use.
- **Counters do not trust the client.** The address is the N-th entry from the right of `X-Forwarded-For` (N trusted proxies);
  what the client puts on the left is never read. A chain that is not what the configuration says gives an *unknown* client, which
  is logged loudly and not counted (bucketing everyone on the proxy address would lock everyone out together).
- **A soft limit asks for more, a hard limit refuses.** Above a soft limit the score that the CAPTCHA demands rises (a shared
  NAT, an office, is not locked out); a hard limit is a flood guard. A refused request is not counted against the shared counters,
  and a guest's recipient counter is counted only after the CAPTCHA passed, so nobody can burn the counter of a victim's address
  without a valid token.
- **An error of the guard never becomes a 500 and never opens a closed action.** The hook passes through every request of the
  site; an unexpected error is logged with its traceback and the fail policy of the action decides.
- **Privacy.** The counters hold a keyed hash of the address or e-mail (HMAC with the site's key), never the value, and expire with
  their window; the log lines hold the action, the outcome and the score, never a token, a secret or an address.

## Rate limit

Counters per action in the cache Redis: `SET key 0 EX window NX` plus `INCR` in one MULTI/EXEC transaction (atomic, no race; the
key has the db-name prefix so sites that share Redis do not share counters). Kinds: `ip`, `account` (the session user),
`recipient` (the address a mail goes to) and `site` (every request of the action). Defaults are in `ratelimit.py` (for example 10
sign-up attempts an hour from one address before the CAPTCHA is made stricter and 60 before it is refused); `guard_limits` tunes
them. Redis down: the fail policy of the action decides. Notes: the cache Redis normally runs with `maxmemory` and an eviction
policy, so a counter can reset under memory pressure; Frappe sets no socket timeout, so a hung Redis blocks the request. Verify
the proxy chain before using `enforce`.

## Browser side

`frappe_guard/public/js/guard.js` (served as `/assets/frappe_guard/js/guard.js`, or inlined in the head of a page) makes the token:

```js
FrappeGuard.init({ siteKey: "<the public site key>" });
const response = await FrappeGuard.request("/api/method/<method>", { action: "contact", method: "POST", body: formData });
```

The provider script loads on the first interaction with a form matching `form[data-guard-action]` (not at page load, and not
behind the analytics banner; it is named in the privacy text as anti-abuse), from `www.google.com`, else `www.recaptcha.net`.
One token is made per request and sent in `X-Guard-Token`. The request asks for JSON (`Accept`, `X-Requested-With`): Frappe
answers any other client with an HTML page on a refusal. The whole token step is capped at 8 seconds; after the provider could
not be reached, requests do not wait for it again for 15 seconds. A failure of the browser side is never thrown: the request goes
without a token and the server decides. The site key is put in the page; do not fetch it. It needs `Promise` and `fetch`;
`request` merges the caller's headers and sets no `credentials` or content type. Load one `api.js?render=` per page. CSP:
`script-src` and `frame-src` need `www.google.com`, `www.recaptcha.net` and `www.gstatic.com`; the badge may be hidden only
together with the disclosure text.

## Reserved names

`guard_token` (a form field) and `X-Guard-Token` (a header) carry the CAPTCHA token; the guard removes the field from every
request before the endpoint sees it, so an endpoint must not use a parameter of that name.

## Install

```
bench get-app https://github.com/tasmail/frappe-guard
bench --site <site> install-app frappe_guard
```

Then set the keys, `guard_hosts` and the mode in the site config (see Configuration). The app is not in any bench yet.

## Development

Python 3.10+, Frappe v15. Tabs, line length 110: `ruff check . && ruff format --check .`. Unit tests (no bench, a stub of
`frappe`): `pytest --cov`; the browser script: `node --test tests/js/guard.test.js`. The integration tests (a site, Redis, the real
router) are still to be written. See `AGENTS.md` for the rules of work.

## Licence

MIT. The idea of the modes and the fail policy comes from reviewing `frappe-contact-form`; no code of it is copied.
