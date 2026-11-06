# frappe_guard

CAPTCHA and rate limit for the public forms and the guest endpoints of Frappe v15 sites (contact forms, sign-up, password reset,
e-mail login link, downloads).

Status: **under construction, nothing is released.** Merged: the skeleton, the check core and the request hook. In review: the
rate limiter and the browser script. Not built yet: protection of the password `login` (it needs its own mechanism, see below;
**`login` is not protected today**), the Press side that installs the app and writes the keys, Cloudflare Turnstile, and the
migration of the code that lives in `fossdoc_shop`. It is not installed on any site yet.
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
Before this app the FOSS-On-Line sites that this was written for (the platform is described in the plan) each carried their own
copy of a CAPTCHA check, with no counters. This app does not replace Frappe's own `@rate_limit` (it stays) and does not overwrite
`frappe.local.request_ip`; it adds its own counters that do not read that value.

## How it works

One hook, `auth_hooks` (`hook.guard_request`), looks at **every** request of the site before Frappe dispatches it:

```
request -> not OPTIONS? -> which method is it? -> is that method guarded? -> mode off? -> stop
                                                                      |
  1. counters that need no token: address, site (a signed-in session: also account and recipient)
        over the soft limit: the CAPTCHA will demand a score +0.2
        over the hard limit: refuse (417; in `monitor` only logged)
                                                                      |
  signed in? -- yes: no CAPTCHA, done
                                                                      |  no (a guest)
  2. CAPTCHA token (header X-Guard-Token or field guard_token), checked with Google reCAPTCHA v3
        missing, invalid, low score, wrong host or action: refuse (417; in `monitor` only logged)
                                                                      |  passed
  3. counter of the recipient (the address a mail goes to)
        over the hard limit: refuse (417; in `monitor` only logged)
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

The map `method -> action` is data: the code holds defaults for the stock Frappe endpoints and for the two FossDoc shop endpoints
(`fossdoc_shop.*`, which exist only on the FossDoc sites); a site adds its own in `guard_action_map`.

| Action | Endpoint (default map) | Why | When the provider is down | Counters besides the address and the site |
| --- | --- | --- | --- | --- |
| `sign_up` | `frappe.core.doctype.user.user.sign_up` | creates an account and mails the address in `email` | refuse (fail closed) | recipient (`email`); account (signed-in only) |
| `reset_password` | `frappe.core.doctype.user.user.reset_password` | mails the user in `user` | pass (fail open) | recipient (`user`); account (signed-in only) |
| `send_login_link` | `frappe.www.login.send_login_link` | mails a login link to `email` | pass (fail open) | recipient (`email`); account (signed-in only) |
| `contact` | `frappe.www.contact.send_message` | sends a message to the company (and, if enabled in Contact Us Settings, an acknowledgement to the sender) | refuse | |
| `download` | `fossdoc_shop.downloads.request_download` | mails download links of the FossDoc demo | refuse | |
| `calculation` | `fossdoc_shop.api.send_calculation` | mails the calculation of the FossDoc shop | refuse | |

*Fail open* for reset and the link (and for the future `login`) is deliberate: a Google outage must not lock customers out of their
accounts; the counters still bound the abuse. The forms and sign-up *fail closed* with a message that asks to try again later.
The same policy governs an outage of Redis (the counters): with Redis down a closed action (the forms, sign-up) refuses everyone in
`enforce`, an open one passes.

**What it does not close.** The password `login` (`cmd=login`, `/api/method/login`) is processed by Frappe's `LoginManager`
inside `HTTPRequest()`, **before any hook**, so this hook cannot see it; it needs its own mechanism (package P7: a wrapper of
`LoginManager.login`, or password login switched off where a shop uses only the e-mail link). Not in scope: the OTP login of
the staff, a WAF, and the edge limit of the proxy (which stays and is extended on the Press side).

## Modes

Every action has a mode: `off` (nothing is checked or counted), `monitor` (checked, counted and logged, **never refused**) or
`enforce` (a failed check or a hard limit is refused with a validation error, HTTP 417, with one of three messages: the check
failed, the check is not available, the check is not configured; or "too many requests"). The default mode is `monitor`; the
rollout plan keeps a site there for at least a week. `enforce` is switched per action in the site config, without a deploy. Only
requests that did not pass are logged, to the `frappe_guard` logger (the action, the outcome, the mode, the score; never a token,
a secret or an address). A mistyped value in `guard_actions` or in `Guard Settings` is ignored **and logged by field name**; an
invalid `guard_limits`, `guard_hosts` or `guard_trusted_hops` is ignored (for `guard_trusted_hops` see below).

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
| `guard_trusted_hops` | the number of trusted proxies; **no default**: until the platform writes the verified value every client is *unknown* (see Rate limit) |
| `guard_ip_header` | the header that carries the client address, default `X-Forwarded-For` |

A site without a secret or host list is *not configured*: it refuses the guarded actions in `enforce` (and passes them in
`monitor`, in developer mode and in tests), so a missing key never opens a form silently.

## Why it is built this way

- **reCAPTCHA v3 first**: the same provider as the code it replaces, no visible challenge. The score is compared with a threshold **per action**; a score of
  0 is honoured; the host in Google's reply must be in `guard_hosts`; `remoteip` is not sent (behind a proxy it is the proxy);
  the action in the reply must be the expected one. A token is single use.
- **Counters do not trust the client.** The address is the N-th entry from the right of `X-Forwarded-For` (N trusted proxies);
  what the client puts on the left is never read. A chain that is not what the configuration says gives an *unknown* client, which
  is logged loudly and not counted (bucketing everyone on the proxy address would lock everyone out together).
- **A soft limit asks for more, a hard limit refuses.** Above a soft limit the score that the CAPTCHA demands rises (a shared
  NAT, an office, is not locked out); a hard limit is a flood guard. A refused request is not counted against the shared counters,
  and a guest's recipient counter is counted only after the CAPTCHA passed, so nobody can burn the counter of a victim's address
  without a valid token.
- **An error of the guard never becomes a 500.** The hook passes through every request of the site. If it cannot tell which method
  a request is, the request passes and the error is logged with its traceback (a bug of the map must not take the site down). If
  the check itself fails, the fail policy of the action decides; if even the configuration cannot be read, the check runs in
  `monitor`: the request passes and the error is logged.
- **What is stored.** The counters hold an HMAC-SHA256 of the address or e-mail, keyed with the site's `encryption_key` (with no
  such key the hash is unkeyed and a guessable e-mail could be recovered from a Redis dump: a warning is logged), and expire with
  their window; no address or e-mail is stored in Redis in readable form. The log lines hold the action, the outcome and the
  score, never a token, a secret or an address.

## Rate limit

Counters per action in the cache Redis: `SET key 0 EX window NX` plus `INCR` in one MULTI/EXEC transaction (atomic, no race; the
key has the db-name prefix so sites that share Redis do not share counters). Kinds: `ip`, `account` (the session user, a signed-in
session only), `recipient` (the address a mail goes to: lowercased, a `+tag` dropped) and `site` (every request of the action).
Each limit is a count per window: above **soft** the CAPTCHA demands a score +0.2 (a shared NAT is not locked out), above **hard**
the request is refused (in `enforce`). Defaults (`ratelimit.py`; `guard_limits` replaces them per kind):

| Actions | Counter | Window | Soft | Hard |
| --- | --- | --- | --- | --- |
| all | `ip` burst | 60 s | 5 | 20 |
| `sign_up`, `reset_password`, `send_login_link` | `ip` | 1 h | 10 | 60 |
| the same | `account` (signed-in) | 1 h | 20 | 20 |
| the same | `recipient` | 1 h | 20 | 20 |
| the same | `site` | 1 h | 200 | 600 |
| `contact`, `download`, `calculation` and any other action | `ip` | 1 h | 20 | 100 |
| the same | `site` | 1 h | 300 | 1000 |

`ip` has two limits (the burst and the hourly one); naming `ip` in `guard_limits` replaces both. The `account` and `recipient`
counters are counted after the CAPTCHA passed (for a guest), so there is no score left to raise: only their hard limit is active.
The kinds are counted in the order address, account, recipient, site, and after the first hard limit nothing more is counted: a
refused request does not feed the shared counters (one address cannot use up the site counter for everyone).

**The address.** It is the N-th entry from the right of `X-Forwarded-For` (N = `guard_trusted_hops`); what the client puts on the
left is never read. `guard_trusted_hops` has **no default**: the proxy chain of the platform must be read and written to the site
config first (package P4). Until then, or when the chain is shorter than configured, the client is *unknown*: it is not counted
per client (a bucket of the proxy address would lock everyone out), the requests of unknown clients are counted per action
(never refused, so the number can be read) and a loud log line is written once per process. Do not use `enforce` before the
chain is verified.

**Known residual risk.** An attacker with valid tokens can use up the recipient cap (20 an hour) of a victim's address and so
block his password reset for the hour. No counter fixes that; the cap bounds the mail bomb instead.

Other notes: the cache Redis normally runs with `maxmemory` and an eviction policy, so a counter can reset under memory
pressure; the guard configures no timeout for Redis, so a hung Redis delays the request.

## Browser side

`frappe_guard/public/js/guard.js` (served as `/assets/frappe_guard/js/guard.js`, or inlined in the head of a page) makes the token:

```js
FrappeGuard.init({ siteKey: "<the public site key>" });
const response = await FrappeGuard.request("/api/method/<method>", { action: "contact", method: "POST", body: formData });
```

The provider script loads on the first interaction with a form matching `form[data-guard-action]` (not at page load, and not
behind the analytics banner; a site must name it in its privacy text as anti-abuse), from `www.google.com`, else `www.recaptcha.net`.
One token is made per request and sent in `X-Guard-Token`. The request asks for JSON (`Accept`, `X-Requested-With`): Frappe
answers any other client with an HTML page on a refusal. The whole token step is capped at 8 seconds; after the provider could
not be reached, requests do not wait for it again for 15 seconds. A failure to get a token is never thrown: the request goes
without a token and the server decides (a failure of `fetch` itself is the caller's). The site key is put in the page; do not fetch it. It needs `Promise` and `fetch`;
`request` merges the caller's headers and sets no `credentials` or content type. Load one `api.js?render=` per page. CSP:
`script-src` and `frame-src` need `www.google.com`, `www.recaptcha.net` and `www.gstatic.com`; the badge may be hidden only
together with the disclosure text.

## Reserved names

`guard_token` (a form field) and `X-Guard-Token` (a header) carry the CAPTCHA token; the guard removes the field from every
request (also from requests that are not guarded) before the endpoint sees it, so an endpoint must not use a parameter of that
name.

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
