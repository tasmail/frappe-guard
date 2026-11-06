# frappe_guard

CAPTCHA and rate limit for the registration, the login and the contact form of Frappe v15 sites (sign-up, password reset, the
e-mail login link and the contact form; the password login is planned, see Status).

Status: **under construction, nothing is released and it is not installed on any site yet.** Merged: the skeleton, the check core,
the request hook, the rate limiter and the browser script. Not built yet: protection of the password `login` (**`login` is not
protected today**), the script for the stock `/login` page (package P6: that page's sign-up, reset and e-mail-link forms send no
token yet), the Press side that installs the app and writes the keys, Cloudflare Turnstile, and the migration of the contact form
of the FossDoc shop (after the migration the check in `fossdoc_shop` remains only for the download and the calculation, which this
app does not cover).
**Cost in short:** microseconds per request that is not guarded; one or two Redis round trips and, for a guest, one call to Google
per guarded request (see Performance).

The plan, the decisions and the work packages are in `docs/guard/plan.md` of the infrastructure repository `tasmail/erpnext-infra`.

## Why

The registration, the login and the contact form of a Frappe site are open to anyone, and bots use them:

- **Mail abuse.** `sign_up`, `reset_password` and `send_login_link` send an e-mail to an address chosen by the caller: an attacker
  makes the site mail a victim thousands of times (and burns the reputation of the sending domain). A contact form is spammed the
  same way, and every acknowledgement is a mail to a stranger.

Frappe's own protection does not cover this: the limit of `@rate_limit` is keyed on `frappe.local.request_ip`, which is the
left-most entry of `X-Forwarded-For` and is chosen by the client (change the header, change the bucket); `sign_up` has no limit
but (by default) 300 new users an hour for the whole site; the limit at the edge (nginx) sees only the path, not a `cmd` in a request body.
Before this app the FossDoc sites each carried their own copy of a CAPTCHA check, with no counters. This app does not replace Frappe's own `@rate_limit` (it stays) and does not overwrite
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
  `/api/v1/method/<m>`, `/api/v2/method/<m>` and `/api/v2/method/<doctype>/<m>`, with or without a trailing slash and, on `/api/method` and
  `/api/v1/method`, with a suffix after the method name (Frappe runs `<m>` for `/api/method/<m>/anything`). The endpoint is recognised by identity, not by name.
- `upload_file` is open to guests and calls the method named in its `method` field, also under any alias
  (`frappe.api.v2.upload_file`, a re-export by a site app): the named method is the requested one.
- The name is matched as requested, before `override_whitelisted_methods`.

**Why a signed-in user is not asked for a CAPTCHA** (any session that is not Guest, also an API key or a bearer token): the
CAPTCHA tells a bot from a person, and the counters (account, recipient, address, site) still apply, because a self-registered
account can abuse `sign_up` and the mail actions too.

## Which endpoints it closes

The map `method -> action` is data: the code holds the defaults for the four stock Frappe endpoints below (the password `login` is
described after the table); a site adds its own in `guard_action_map`. The download and the calculation of the FossDoc shop keep
the CAPTCHA check that lives in `fossdoc_shop`: this app does not cover them.

| Action | Endpoint (default map) | Why | When the provider is down | Counters besides the address and the site |
| --- | --- | --- | --- | --- |
| `sign_up` | `frappe.core.doctype.user.user.sign_up` | creates an account and mails the address in `email` | refuse (fail closed) | recipient (`email`); account (signed-in only) |
| `reset_password` | `frappe.core.doctype.user.user.reset_password` | mails the user in `user` | pass (fail open) | recipient (`user`); account (signed-in only) |
| `send_login_link` | `frappe.www.login.send_login_link` | mails a login link to `email` | pass (fail open) | recipient (`email`); account (signed-in only) |
| `contact` | `frappe.www.contact.send_message` | sends a message to the company (and, if enabled in Contact Us Settings, an acknowledgement to the sender) | refuse | |

*Fail open* for reset and the link (and for the future `login`) is deliberate: a Google outage must not lock customers out of their
accounts; the counters still bound the abuse. The forms and sign-up *fail closed* with a message that asks to try again later.
The same policy governs an outage of Redis (the counters): with Redis down a closed action (the forms, sign-up) refuses everyone in
`enforce`, an open one passes.

**What it does not close.** The download (`fossdoc_shop.downloads.request_download`) and the calculation
(`fossdoc_shop.api.send_calculation`) of the FossDoc shop keep their own check inside `fossdoc_shop`. Other guest endpoints of Frappe (newsletter `subscribe`, which mails a confirmation to an address the
caller chooses, Web Form `accept`, the comment `add_comment`, and any app's own) are **not guarded until a site adds them** to
`guard_action_map`; a custom action has the address and site counters but no recipient counter. The password `login` (`cmd=login`, `/api/method/login`) is processed by Frappe's `LoginManager`
inside `HTTPRequest()`, **before any hook**, so this hook cannot see it; it needs its own mechanism (package P7: a wrapper of
`LoginManager.login`, or password login switched off where a shop uses only the e-mail link). Not in scope: the OTP login of
the staff, a WAF, and the edge limit of the proxy (which stays and is extended on the Press side).

## Modes

Every action has a mode: `off` (nothing is checked or counted), `monitor` (checked, counted and logged, **never refused**; only
what did not pass is logged) or
`enforce` (a failed check or a hard limit is refused with a validation error, HTTP 417, with one of four messages: the check
failed, the check is not available, the check is not configured, or "too many requests"). The default mode is `monitor`; the
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
| `guard_hosts` | the host names of THIS site the tokens are accepted from (its public and internal names, or its QA names); a token made on another host is refused. One reCAPTCHA key pair may serve many sites: the list of each site is what keeps a token of one site from passing on another |
| `guard_mode` | the default mode of every action (`off`, `monitor`, `enforce`) |
| `guard_actions` | `{action or "*": {"mode", "threshold", "fail", "provider_action"}}` |
| `guard_action_map` | `{"dotted.method": "action"}`: the endpoints of a site |
| `guard_limits` | `{action: [{"kind", "window", "soft", "hard"}]}`: the counters, replaced per kind |
| `guard_trusted_hops` | the number of trusted proxies; **no default**: until the platform writes the verified value every client is *unknown* (see Rate limit) |
| `guard_ip_header` | the header that carries the client address, default `X-Forwarded-For` |

A site without a secret or host list is *not configured*: it refuses the guarded actions in `enforce`; in `monitor` it passes them
and logs `outcome=not_configured` for each (look for it in the first hours of the rollout week); in developer mode and in tests it
passes them silently. Outside developer mode a missing key never opens a form in `enforce`.

## Why it is built this way

- **reCAPTCHA v3 first**: the same provider as the code it replaces, no visible challenge. The score is compared with a threshold **per action**; a score of
  0 is honoured; the host in Google's reply must be in `guard_hosts`; `remoteip` is not sent (behind a proxy it is the proxy);
  the action in the reply must be the expected one. Google rejects a reused token.
- **Counters do not trust the client.** The address is the N-th entry from the right of `X-Forwarded-For` (N trusted proxies);
  what the client puts on the left is never read. A chain shorter than configured, or an entry that is not an address, gives an *unknown* client (a chain longer than configured is
  not detected: the N-th entry from the right is taken): logged loudly,
  not counted per client (bucketing everyone on the proxy address would lock everyone out together) and counted in a per-action
  `unknown` counter that never refuses.
- **A soft limit asks for more, a hard limit refuses.** Above a soft limit the score that the CAPTCHA demands rises (a shared
  NAT, an office, is not locked out); a hard limit is a flood guard. A request refused by the address or account hard limit does not feed the
  site counter, and a guest's recipient counter is counted only after the CAPTCHA passed, so nobody can burn the counter of a victim's address
  without a valid token.
- **An error of the check, the map or the counters never becomes a 500.** The hook passes through every request of the site. If it cannot tell which method
  a request is, the request passes and the error is logged with its traceback (a bug of the map must not take the site down). If
  the check itself fails, the fail policy of the action decides; if even the configuration cannot be read, the check runs in
  `monitor`: the request passes and the error is logged.
- **What is stored.** The counters hold an HMAC-SHA256 of the address or e-mail, keyed with the site's `encryption_key` (with no
  such key the hash is unkeyed and a guessable e-mail could be recovered from a Redis dump: a warning is logged), and expire with
  their window; no address or e-mail is stored in Redis in readable form. The log lines hold the action, the outcome and the
  score, never a token, a secret or an address.

## Rollout

The default mode is `monitor`: nothing is refused. **Do not enforce `sign_up`, `reset_password` or `send_login_link` on a site that uses the stock `/login` page** until the script of
package P6 exists: the forms of that page send no token, they would be refused.
To enforce one action, in the site config:

```json
{"guard_recaptcha_site_key": "...", "guard_recaptcha_secret": "...", "guard_hosts": ["www.example.com"],
 "guard_trusted_hops": 1, "guard_actions": {"contact": {"mode": "enforce"}}}
```

`1` is a placeholder: set the verified number of trusted proxies (the launch plan expects 2); until then every client is unknown.
To go back, set the mode to `monitor` or `off`. A change of the site config applies at once (it is read on every request); a change
of `Guard Settings` reaches each worker process within 30 seconds; a failed read of it keeps serving the last good values and is retried after 3 seconds. The threshold is 0.5 per action (`guard_actions: {"contact": {"threshold": 0.7}}`); above a soft limit it is raised by
0.2, at most to 1.0. The `action` that the browser passes to `FrappeGuard.request` is the action of the reCAPTCHA token and must
equal the action name above (or `provider_action` if set): a token made for another action is refused (`action_mismatch`). The
call to Google has 1.5 seconds to connect and 2.5 to read (normally at most about 4 seconds; a provider that trickles bytes or a slow DNS lookup can take longer), reuses its connection, is made at most 20
at a time per process, and after 5 failures in a row it is not made for 15 seconds (the fail policy answers at once). A refusal is HTTP 417 with one of: "The check of the form failed. Reload the page and try
again.", "The check of the form is not available now. Try again later.", "The check of the form is not configured" or "Too many
requests. Try again later." A line of the log (`frappe_guard` logger): `action=sign_up outcome=low_score mode=monitor allow=True score=0.1`;
a soft limit is not logged, a hard limit and a failed check are.

## Performance

The hook runs on every request of a site, so its cost is pinned by tests (`tests/test_performance.py`), not only measured:

- A request that is not guarded (a page, `/api/resource`, any other method): **no Redis, no database query, no call to the
  provider** (apart from two rare cases: a name sent together with a `method` field is resolved once per process and site, and a
  `/api/v2/method/<doctype>/<method>` whose method name is a guarded one, or that carries a `method` field, loads the doctype module). The Python cost with a stub of
  Frappe (`scripts/bench_hook.py`): about 1 microsecond for a page, about 20 for an `/api/method` call (the router match), 1 to 3 for a
  `cmd` call; the real `frappe.local` is slower than the stub, but this stays microseconds to a few tens of microseconds, negligible
  against the request itself.
- A guarded request: **one round trip to Redis per counter phase** (all the counters of a phase in one MULTI/EXEC), so one for a
  form, two for a guest's `sign_up` (the second after the CAPTCHA), one for a signed-in session; about 60 to 100 microseconds of
  Python on top (measured with a stub of Redis; the real client adds some tens of microseconds), plus the round trips. A refused request costs at most one more round trip to give the counts back.
- `Guard Settings` is read from the database once per process per 30 seconds, not per request (Frappe's own value cache lives for one
  request only).
- The only slow step is the call to Google for a **guest's guarded request** (a form, a sign-up): typically one round trip over a
  kept connection, normally at most about 4 seconds (a trickling provider or a slow DNS lookup can take longer), on the worker that serves the request; it is capped at 20 calls at a time per process
  and stopped for 15 seconds after 5 failures in a row, so a slow provider cannot hold every worker. The counters of address and
  site run **before** it: once a hard limit is exceeded the request is refused without calling Google.
- In the browser the script loads on the first touch of a form, not at page load, so the page itself is untouched; a submit waits
  for one token (the cap is 8 seconds; a provider outage costs that wait once, then 15 seconds without waiting). Measure the time of
  the forms in the monitor week.
- A hung Redis delays the requests of the guarded actions (the guard sets no timeout), a Redis that is down follows the fail policy.

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
| `contact` and any other action | `ip` | 1 h | 20 | 100 |
| the same | `site` | 1 h | 300 | 1000 |

`ip` has two limits (the burst and the hourly one); naming `ip` in `guard_limits` replaces both. The `account` and `recipient`
counters are counted after the CAPTCHA passed (for a guest), so there is no score left to raise: only their hard limit is active.
Signed in: address, account, recipient and site are counted (in that order); a guest: address and site, then the recipient, after
the CAPTCHA passed (or when the request is not being refused: in `monitor`, or on a site that is not configured). After the first hard limit nothing more is counted (the counts are given back): a request refused by the
address or account limit does not feed the site counter (one address cannot use up the site counter for everyone). A request
refused for its CAPTCHA, or for the recipient cap, has already been counted by address and site.

**The address.** It is the N-th entry from the right of `X-Forwarded-For` (N = `guard_trusted_hops`); what the client puts on the
left is never read. `guard_trusted_hops` has **no default**: the proxy chain of the platform must be read and written to the site
config first (package P4). Until then, or when the chain is shorter than configured, the client is *unknown*: it is not counted
per client (a bucket of the proxy address would lock everyone out), the requests of unknown clients are counted per action under
`unknown` (that counter never refuses, so the number can be read) and a loud log line is written once per process. While
`guard_trusted_hops` is unset there is no per-client limit at all, and the `site` limit only raises the score for unknown clients,
never refuses (one client must not be able to lock everyone out); the CAPTCHA and the recipient and account caps stay. The address
of an IPv6 client is its /64, an IPv4-mapped address is its IPv4 address, ports are stripped. Do not use `enforce` before the
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
