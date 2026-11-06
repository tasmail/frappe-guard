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
