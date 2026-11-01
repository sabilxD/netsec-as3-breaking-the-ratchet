## 5. Attack 2 — malicious server / MITM (identity-key substitution)

> **[Authored by 23b1057 — to be completed.]**
>
> Planned content: trust-model analysis (how Alice obtains Bob's bundle, how identity
> keys are—or are not—verified), the key observation already seen in the logs that the
> **signed-prekey signature is not verified** (`warn: SPK sig NOT verified`), the
> malicious-server PoC that substitutes identity/prekey material to run separate
> sessions with Alice and Bob, evidence of a forwarded message vs. a recovered plaintext
> vs. an auth failure, and Python-style fix pseudocode (verify `spk_sig` against the
> identity key; out-of-band identity verification / safety numbers; TOFU pinning).
