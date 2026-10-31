# Breaking the Ratchet — Technical Report (rollno1 sections)

> Sections authored by rollno1: Introduction, Protocol overview, Attack 0.
> Attack 1 and Attack 2 sections are authored by rollno2 and merged into the final
> `report_rollno1_rollno2.pdf`.

## 1. Introduction

The lab implements Signal-style end-to-end encryption: an **X3DH** key agreement that
seeds a **Double Ratchet** session, with the server acting only as a relay/mailbox
(`send` queues a frame, `poll` collects it). We analysed the implementation from
`protocol.md`, the client/server logs, and packet captures of the newline-delimited JSON
on TCP port 9000. This report documents the implementation flaws we found and gives
Python-style fix pseudocode for each.

## 2. Protocol overview (as implemented)

- **Primitives:** X25519 (DH), Ed25519 (SPK signature), HKDF-SHA256 (KDF),
  ChaCha20-Poly1305 (AEAD, zero nonce — safe because each `mk` is single-use).
- **Bundle:** identity (`ik_sig`, `ik_dh`), signed prekey `spk` + `spk_sig`, and
  one-time prekeys `opk` with integer ids.
- **Frame header:** `dh` (sender ratchet pubkey), `pn` (previous sending-chain length),
  `n` (message number in current chain), and an `init` block on the first message only.
- **Ratchet:** the header is bound as AEAD associated data (`ad = AD + serialize(header)`),
  so a tampered header makes the *final* decrypt fail — but, as Attack 0 shows, only
  after the receiver has already done counter-driven work.

## 3. Attack 0 — skipped-key resource exhaustion via counter manipulation

### 3.1 The flaw

`ratchet_decrypt` (protocol.md §4.4) advances and **stores** skipped message keys
*before* the AEAD tag is verified:

```python
def ratchet_decrypt(st, header, ct):
    ...
    skip_message_keys(st, header["n"])   # derives + stores keys up to header["n"]
    mk, st.CKr = kdf_ck(st.CKr)
    return aead_decrypt(mk, ct, st.AD + serialize(header))  # only now is auth checked

def skip_message_keys(st, until):
    if until - st.Nr > MAX_SKIP:          # MAX_SKIP = 1000
        raise Error("too many skipped messages")
    while st.Nr < until:
        mk, st.CKr = kdf_ck(st.CKr)
        st.skipped[(st.DHr, st.Nr)] = mk  # unbounded store, no global cap
        st.Nr += 1
```

Two problems compound:

1. **Work before authentication.** The header's `n` is attacker-controlled on-path and
   is honoured *before* the tag check. A forged `n` forces up to `MAX_SKIP` HMAC
   derivations even though the frame never decrypts.
2. **No global cap on stored keys.** `MAX_SKIP` bounds *one* step, but `st.skipped`
   accumulates across frames. Streaming forged frames grows CPU and memory without
   bound.

### 3.2 The attack

Mallory is a transparent TCP proxy on Bob's path to the server (the assignment's Mallory
position). She forwards everything unchanged except that in each delivered `Frame` she
rewrites the header's `n` to `real_n + gap`, with `gap ≤ MAX_SKIP` so the receiver takes
the expensive skip loop rather than the cheap early `raise`. She leaves `dh` unchanged so
processing stays on Bob's current receiving chain. See `attacks/attack0.cpp`.

Per forged frame, Bob performs up to ~`gap` HMAC derivations and stores ~`gap` keys; the
frame then fails authentication and is dropped — but the damage persists in `st.skipped`.

### 3.3 Assumptions

1. Header counters travel in cleartext JSON and are modifiable on-path.
2. The receiver derives/stores skipped keys before verifying the AEAD tag.
3. Skipped keys accumulate with no session-wide bound.
4. Mallory is on the Bob↔server path.

### 3.4 Impact measurement

We drove forged frames at increasing `gap` and sampled Bob's container with
`docker stats` (`scripts/measure.py`), then plotted CPU% and memory vs gap
(`scripts/plot.py`). Expected result: per-frame CPU rises ~linearly with `gap` up to the
`MAX_SKIP` knee, and memory grows monotonically as `st.skipped` fills — a single on-path
attacker degrades Bob with unauthenticated frames. *(Insert `results/attack0.png` and the
measured table here.)*

### 3.5 Fix

Authenticate before doing counter work, and bound stored keys globally:

```python
MAX_SKIP        = 1000      # per ratchet step
MAX_SKIP_TOTAL  = 2000      # hard cap on simultaneously stored skipped keys

def ratchet_decrypt(st, header, ct):
    # 1) Reject implausible jumps up front (cheap, before any derivation).
    if header["n"] - st.Nr > MAX_SKIP or header["pn"] - st.Nr > MAX_SKIP:
        raise Error("counter gap too large")

    mk = try_skipped_keys(st, header)
    if mk is not None:
        return aead_decrypt(mk, ct, st.AD + serialize(header))  # may raise -> drop

    # 2) Derive ONLY the single key this frame claims, speculatively, and verify the
    #    tag BEFORE committing any skipped-key storage.
    trial = clone(st)                     # work on a copy; commit only on success
    if header["dh"] != trial.DHr:
        _bounded_skip(trial, header["pn"])
        dh_ratchet(trial, header)
    _bounded_skip(trial, header["n"])
    mk, trial.CKr = kdf_ck(trial.CKr)
    pt = aead_decrypt(mk, ct, st.AD + serialize(header))   # raises on bad tag -> no commit
    commit(st, trial)                      # only reached if authentication passed
    return pt

def _bounded_skip(st, until):
    if until - st.Nr > MAX_SKIP:
        raise Error("too many skipped messages")
    if len(st.skipped) + (until - st.Nr) > MAX_SKIP_TOTAL:
        raise Error("skipped-key store full")   # global cap -> no unbounded memory
    while st.Nr < until:
        mk, st.CKr = kdf_ck(st.CKr)
        st.skipped[(st.DHr, st.Nr)] = mk
        st.Nr += 1
```

Key ideas: (a) verify the AEAD tag on a *copy* of the state and commit only on success,
so a forged header causes no lasting work or storage; (b) cap total stored skipped keys
(`MAX_SKIP_TOTAL`), evicting or refusing beyond it, so memory cannot grow without bound.
```
