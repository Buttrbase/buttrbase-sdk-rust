# ButtrBase Documentation — Gaps & Improvement Plan

_Grounded in primary sources (2026-07-18): the public site `https://buttrbase.com/docs`,
this SDK's `README.md` (1181 lines) + `src/client.rs` public API, and a real consumer
(`zlack_server/src/buttrbase.rs`, plus `zlack_client_slint` which links this SDK)._

## TL;DR — the one finding that matters most

**The API is well documented at the SDK level and effectively undocumented at the
public level.** `https://buttrbase.com/docs` renders to essentially a single
`ButtrBase` heading — no API reference, no getting-started, no credential guide,
no endpoint list. Meanwhile this SDK's `README.md` already covers 40+ areas
(registration, OTP, magic link, passkeys, SSO, MFA, RBAC, teams, invitations,
billing, entitlements, credentials, analytics, webhooks, …).

So the highest-leverage improvement is not "write docs from scratch" — it's
**publish and generalize what already exists in this README**, and fix the
credential story, which is the single most confusing part for a new integrator.

---

## P0 — Credentials & keys are fragmented and unnamed (biggest real blocker)

A new integrator asks one question first: _"I have keys — how do I install them so
my app can log users in and register orgs?"_ Today that question has no clean answer,
for three reasons:

1. **Terminology is inconsistent across surfaces.** The dashboard/console (and how
   people refer to them) calls them **`access_id` + `secret_key`**. This SDK calls
   them **`client_id` + `client_secret`** (`ButtrBaseClient::new(client_id, client_secret)`,
   `src/client.rs:60`). The README *also* has separate sections for **"API Keys (v2)"**,
   **"Service Identities"**, and **"Credentials Management"**. Nowhere is it stated
   whether these are the same thing, four different things, or a hierarchy.
   - **Fix:** one canonical **"Keys & Credentials"** page that names each credential
     type once, states its purpose, and maps the dashboard label ↔ SDK field ↔ API
     field. If `access_id == client_id` and `secret_key == client_secret`, say so in
     one sentence at the top; if they differ, draw the table.

2. **No "install into your app" quickstart.** The README shows
   `ButtrBaseClient::new(id, secret)` but never documents the **env-var convention**
   a backend should use to inject them (e.g. `BUTTRBASE_CLIENT_ID` /
   `BUTTRBASE_CLIENT_SECRET`, or whatever the standard is). Every integrator has to
   invent their own names.
   - **Fix:** publish the canonical env-var names + a 5-line "read from env → build
     client" snippet, and a matching "set these as secrets in your host" note
     (Fly/Heroku/etc.).

3. **Live vs sandbox host isn't in the credential story.** The SDK hardcodes
   `LIVE_BASE_URL = https://api.buttrbase.com` and
   `SANDBOX_BASE_URL = https://stagingapi.buttrbase.com` (`src/client.rs:41-42`),
   selected by an `Environment`. A public integrator has no way to know which host a
   given key pair is scoped to, or how to switch.
   - **Fix:** document the two hosts, that keys are environment-scoped, and how the
     SDK picks the host from `Environment`.

---

## P0 — Publish a public API reference (the README is a ready seed)

The public docs should have a browsable reference for the surface this SDK already
exercises. From `src/client.rs`, that surface includes at least:

- **Auth / sign-in:** `send_otp` / `verify_otp` (+ `_legacy`), `send_magic_link` /
  `verify_magic_link`, `refresh_token`, email/password, passkeys (WebAuthn),
  SSO (OIDC/SAML), `auth_status`.
- **Registration / orgs:** `check_org_name`, `register`, `finalize_registration`,
  org-by-domain, org security, teams, invitations
  (`create` / `preview` / `accept` / `list` / `revoke`).
- **Token verification:** JWTs verified **locally via JWKS** at
  `{base_url}/.well-known/jwks.json` (`src/client.rs:94`) — issuer-pinned, `aud`
  intentionally not pinned. This is a load-bearing detail for anyone building a
  backend verifier and it is easy to miss.
- **Entitlements / billing:** `check_entitlement(s)`, `effective_entitlements`,
  pricing/quote/checkout, wallet, subscriptions, billing history, coupons/gift cards.
- **Usage / analytics:** `report_usage`, `ingest_event`, app/org analytics overviews.

**Fix:** generate an endpoint reference (path, method, auth requirement — *app
credential vs user bearer* — request/response schema, error codes). Even an
OpenAPI spec published at `buttrbase.com/docs` would close most of this gap and could
be generated from the same source of truth the SDK is built against.

---

## P1 — Backend integration guidance (the "which client do I use" gap)

Real evidence of the gap: a production consumer, `zlack_server/src/buttrbase.rs`,
**hand-rolls its own HTTP client** (`BUTTRBASE_URL` + bearer-forwarding to
`/api/auth/status`, `/api/v2/organizations/{org}/members`,
`/api/entitlements/check`, `/api/organizations/{org}/invitations`,
`/api/auth/invitations/{token}/accept`) instead of using this SDK — because there is
no non-Rust SDK and no documented raw-REST contract to code against. It even carries a
`BUTTRBASE_URL=mock` short-circuit for local dev.

- **Fix:** a **"Backend integration"** guide that states, per language: use the SDK
  (Rust today) *or* the documented REST contract; how app-credential auth differs from
  user-bearer auth per endpoint; and a documented "mock/sandbox" mode so teams aren't
  each inventing `BUTTRBASE_URL=mock`.
- **Fix:** note the `jsonwebtoken 10` crypto-provider gotcha (already in the README's
  "Compatibility & gotchas") *in the public verifier docs too* — it's a real footgun
  for anyone verifying tokens.

## P1 — Getting-started path is missing end-to-end

There's no single "zero to logged-in-user + first org" walkthrough. The pieces exist
(Client Setup → Authentication → Organization Invitations → Teams) but aren't strung
into one copy-pasteable path.

- **Fix:** one quickstart: create app + keys in console → install keys (env) → verify a
  user token → register an org → invite a member. This is exactly the flow integrators
  hit first and the one with the least documentation today.

## P2 — Consistency & discoverability

- **Version the API surface.** The README mixes "API Keys (v2)", "Passwordless OTP
  (v2)", and non-versioned endpoints. Document what `v2` means and the deprecation
  status of the `_legacy` OTP calls (`send_otp_legacy` / `verify_otp_legacy` exist in
  the SDK with no stated lifecycle).
- **Surface the README publicly.** 1181 lines of good SDK docs are invisible to anyone
  who hasn't cloned the repo. Mirror the sectioned content onto `buttrbase.com/docs`.
- **Error catalog.** The SDK has a typed `Error`/`verify::error` module; the public
  docs have no error reference. Publish the error codes + remediation.

---

## Suggested public-docs table of contents

1. **Getting started** — create an app, get `access_id`/`secret_key` (= client_id/secret),
   sandbox vs live, install keys (env-var convention), first authenticated call.
2. **Keys & Credentials** — the canonical credential map (dashboard ↔ SDK ↔ API):
   app credentials, API Keys v2, Service Identities, Credentials Management — what each
   is and when to use it.
3. **Authentication** — OTP, magic link, passkeys, SSO, password, refresh; **token
   verification via JWKS** (issuer, no-aud-pin, crypto-provider gotcha).
4. **Organizations & Teams** — register/create org, org-by-domain, security, teams,
   the full invitation lifecycle.
5. **Entitlements & Billing** — checks, pricing, checkout, wallet, subscriptions,
   coupons, usage reporting.
6. **API Reference** — per-endpoint (path, method, auth: app-credential vs user-bearer,
   request/response, errors). Ideally an OpenAPI spec.
7. **SDKs & Backend Integration** — Rust SDK; documented REST for other languages;
   mock/sandbox mode; webhooks; lifecycle jobs.

---

## Concrete next actions (in priority order)

1. Write the **Keys & Credentials** page + reconcile the `access_id/secret_key` ↔
   `client_id/client_secret` naming (one sentence, top of the page).
2. Publish the env-var install convention + backend quickstart.
3. Stand up an API reference / OpenAPI at `buttrbase.com/docs` (currently empty).
4. Add the backend-integration guide (SDK-or-REST, app-cred vs user-bearer, JWKS
   verification, mock mode) so consumers stop hand-rolling clients.
