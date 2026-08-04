# ADR 0001: Explicit Outlook mailbox access mode

- Status: Accepted
- Date: 2026-08-04

## Context

CodeRelay historically treated every four-part Outlook credential as an Outlook IMAP OAuth credential. It always requested `https://outlook.office.com/IMAP.AccessAsUser.All` and then used IMAP XOAUTH2.

A real credential demonstrated a different capability set: an explicit IMAP-scope refresh failed with `invalid_grant`, while the same client ID and refresh token succeeded when `scope` was omitted and produced a Microsoft Graph token with delegated `User.Read` and mail permissions. That access token worked with Microsoft Graph mail APIs and was rejected by both Outlook IMAP endpoints.

The opaque refresh token does not safely encode which mailbox access path the caller intends. Re-probing IMAP and Graph on every stateless request would add a predictable failed OAuth request, obscure `invalid_grant`, increase throttling, and complicate refresh-token rotation ownership.

## Decision

1. The public `outlook` request accepts `mail_access: "imap" | "graph"`.
2. Omitting `mail_access` preserves the historical `imap` behavior.
3. CodeRelay does not automatically fall back between IMAP and Graph.
4. IMAP refresh requests keep the explicit fixed IMAP scope.
5. Graph refresh requests omit the `scope` field and preserve the original delegated grant.
6. Graph mode requires delegated `User.Read` plus `Mail.Read` or `Mail.ReadWrite` when the token response exposes scopes. `Mail.ReadBasic` alone is insufficient.
7. Graph mode verifies that the credential email matches `/me.mail` or `/me.userPrincipalName` before reading mail.
8. Graph mode accesses only the fixed global Microsoft Graph v1.0 endpoint and only uses GET for Graph resources. It never sends, updates, marks, or deletes mail.
9. Graph mode lists only Inbox, uses bounded preview-first extraction, and falls back to bounded MIME `$value` retrieval.
10. Graph polling state, message IDs, access tokens, messages, and codes remain request-scoped. No delta token, subscription, or cross-request cache is introduced.
11. Existing `credential_update.refresh_token` rotation delivery remains unchanged for both modes and for success and error responses.
12. The production implementation uses the hardened standard-library HTTP client rather than the Microsoft Graph SDK, so redirects, proxies, response bounds, cancellation, retry limits, and diagnostics remain locally enforceable.

## Consequences

- Callers with Graph-authorized credentials must explicitly send `mail_access: "graph"` and persist that non-secret metadata alongside the credential.
- Existing callers that omit the field continue to use IMAP without a behavior change.
- Graph credentials are never intentionally presented to IMAP, and IMAP credentials are never intentionally presented to Graph.
- Graph mode adds an identity request and may add MIME GETs, but request-local deduplication prevents repeated MIME downloads during polling.
- A rollback to a pre-Graph CodeRelay binary cannot serve Graph-mode callers; consumer feature flags must be rolled back at the same time.
- If production evidence later shows that IMAP has no users, removing IMAP requires a separate ADR and release.

## References

- [Microsoft identity platform refresh tokens](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)
- [Microsoft Graph: List messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0)
- [Microsoft Graph: Get message and MIME `$value`](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/en-us/graph/throttling)

## Rejected alternatives

- Delete `scope` and continue with IMAP: the returned token has the wrong audience/capability.
- Probe IMAP and then Graph on every request: repeated failure, throttling, ambiguous errors, and rotation risk.
- Route by unverified JWT claims: token claims are not an authorization decision.
- Persist Graph delta links or subscriptions: conflicts with CodeRelay's stateless request-scoped model.
- Replace IMAP in the same change: unnecessarily enlarges the regression and rollback surface.
