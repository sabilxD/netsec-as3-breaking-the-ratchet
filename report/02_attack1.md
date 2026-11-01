## 4. Attack 1 — one-time prekey exhaustion ("Prekey Pogo")

> **[Authored by 23b1057 — to be completed.]**
>
> Planned content: prekey lifecycle analysis (generation, publish, append semantics,
> whether `fetch_bundle` consumes an OPK, concurrency), the malicious-client PoC that
> drains Bob's OPK inventory, measured OPK `count` draining to zero, the resulting
> denial of new sessions, and Python-style fix pseudocode (authenticated/rate-limited
> fetch, OPK reservation, fallback to signed-prekey-only X3DH).
>
> Cross-reference (observed during Attack 0 runs): `publish` **appends** OPKs and the
> server can hand out stale OPKs from an earlier publish, which breaks X3DH for a fresh
> initiator — relevant to this attack's root cause.
