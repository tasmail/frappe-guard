# AGENTS.md

Rules for AI coding agents and humans working in this repository. The plan of the app is
`docs/guard/plan.md` in `tasmail/erpnext-infra` (PR #329); the rules of that repository's `AGENTS.md` apply here too.

## Scope and status

The app covers the registration, the login and the contact form of a Frappe v15 site: `sign_up`, `login`, `send_login_link`,
`reset_password`, `contact`. Nothing else is covered by default (the download and the calculation of the FossDoc shop keep their
own check in `fossdoc_shop`); do not widen the default map without the owner's word, a site opts in by configuration.
Built and merged: the skeleton, the check core, the `auth_hooks` hook, `guard.js`, the rate limiter. Not built: the password `login`
(it is processed before any hook), the script of the stock `/login` page, the contact form migration, Turnstile. Nothing is
installed on a site yet. The plan and the Press side (`press_guard_site.yml`, the release group) are in `tasmail/erpnext-infra`
(`docs/guard/plan.md`); the README of this repository says what the guard closes, how it works and why.

## How work is done

Every task, however small, goes through these steps:

1. **Analysis.** Read the code, the docs and the real state; write down what is known and what is not.
2. **Grilling.** Put every decision the analysis could not settle to the owner, in rounds, each with a recommended answer.
   If none is open, say "no open decisions".
3. **Plan**, in writing: scope, non-goals, files, side effects, risks, rollback, verification, decisions for the owner.
4. **Plan review** by an independent reviewer (a person or a fresh agent session with no shared context, given the plan and
   the sources, not the author's conclusions): APPROVE or CHANGES-NEEDED. The author reading their own plan is not a review.
5. **Implementation** on a branch, only after step 4.
6. **Pull request** with the plan and the plan review in the description. It is reviewed on its exact current head by an
   independent reviewer; the review is a PR comment naming the head SHA. A later commit needs a new review.
7. **Merge** only on the owner's command, only the reviewed head, after checking the PR state and CI.
8. **Deploy** (a bench build, installing the app on a site, a site config, a mode switch to `enforce`) only on the owner's
   explicit command, each time, QA before production. The deploy tooling lives in `tasmail/erpnext-infra`.

Plan approval never authorises a side effect, a merge or a deploy. Nothing is pushed to `main`; check a PR with
`gh pr view <n> --json state,headRefName` before touching it, and never reuse a merged or closed branch.

## Rules

- **English everywhere** in the repository: code, comments, commits, PRs, docs, messages. No AI attribution, no
  `Co-Authored-By`, no session links, no model names.
- **Secrets never reach the console, a log, the model or a commit.** A script reads them internally and prints names,
  lengths or success. The guard never logs a token or a secret value, nor a full client IP.
- **Never end with uncommitted changes**: commit and push on a branch, or ask.
- **Do not claim what is not true** in the README or the texts (no GDPR, SLA or compatibility claims that are not tested).
- No `override_whitelisted_methods`; one choke point; a Frappe upgrade is guarded by the version-pin test.

## Code conventions

- Frappe v15 only (`frappe>=15,<16` in `[tool.bench.frappe-dependencies]`, `dependencies = []` in `pyproject.toml`), flit,
  Python `>=3.10`.
- **Tabs**, line length 110 (`ruff format`).
- Commit messages: one imperative English sentence without a prefix ("Add ...", "Fix ..."), one logical change per commit.
- Unit tests run without a bench against a `frappe` stub (`tests/conftest.py`); integration tests need a site and Redis
  (`dev-bench/run.sh test frappe_guard` in the infrastructure repository).
- Format and lint locally before a push; run the regression tests in PR CI on the exact head.
