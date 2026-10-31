# State-diagram reference (A1 → B3)

> This is a **drawing aid**, not the deliverable. The submission `state_diagram` must be
> the **hand-drawn** figure (photo/scan), brought to the viva. Use the trace below to
> draw it mechanically. Symbolic ids only (no real crypto values), per the assignment.

## Notation
- `DHA0, DHA1` = Alice's ratchet key pairs; `DHB0, DHB1` = Bob's. `SPK_B` = Bob's signed
  prekey (Bob's initial ratchet key on the receiver side).
- `RK0..RK4` = root keys. `CK_A0, CK_A1` = Alice-origin sending chains; `CK_B0, CK_B1` =
  Bob-origin sending chains. `CK_x_k` = that chain after `k` symmetric steps.
- `MK_*` = message key for a given message. `DH(P.priv, Q)` = X25519(P.priv, Q.pub).
- A **DH ratchet** does the two root steps in `dh_ratchet()`; a **symmetric step** is one
  `kdf_ck`.

## Root-key chain (spine of the diagram)
```
RK0 (= sk from X3DH)
  │  DH(DHA0, SPK_B)      ← Alice init_sender AND Bob's ratchet on receiving A1
  ▼
RK1
  │  DH(DHB0, DHA0)       ← Bob's ratchet on receiving A1 (2nd step) / Alice on B1
  ▼
RK2
  │  DH(DHA1, DHB0)       ← Alice's ratchet on receiving B1 / Bob on A3
  ▼
RK3
  │  DH(DHB1, DHA1)       ← Bob's ratchet on receiving A3 / Alice on B3
  ▼
RK4
```
Each arrow is used **twice** (once by each party) — that is what makes their chains line
up. Mark on the drawing which chain key each root step emits (CKr on the receiver side,
CKs on the sender side).

## Initial state after X3DH (before A1)
| | RK | DHs | DHr | CKs | CKr | Ns | Nr | PN |
|--|--|--|--|--|--|--|--|--|
| Alice | RK1 | DHA0 | SPK_B | CK_A0 | – | 0 | 0 | 0 |
| Bob | RK0 | SPK_B | – | – | – | 0 | 0 | 0 |

(Alice's `init_sender` already did `RK0→RK1` and produced `CK_A0`. Bob ratchets only when
A1 arrives.)

## Per-message trace
| # | Sender | header `dh, n, pn` | transition | key derived | chain correspondence |
|--|--|--|--|--|--|
| **A1** | Alice | DHA0, 0, 0 | symmetric step on CK_A0 | MK_A1 = kdf_ck(CK_A0) → CK_A0_1 | Alice send `CK_A0` |
| | Bob recv A1 | | **DH ratchet** (DHr None→DHA0): RK0→RK1 gives CKr=CK_A0; RK1→RK2 gives CKs=CK_B0; new DHs=DHB0 | MK_A1 = kdf_ck(CK_A0) | Bob recv `CK_A0` **=** Alice send `CK_A0` |
| **A2** | Alice | DHA0, 1, 0 | symmetric step | MK_A2 = kdf_ck(CK_A0_1) → CK_A0_2 | same chain `CK_A0` |
| | Bob recv A2 | | no ratchet (dh unchanged) | MK_A2 = kdf_ck(CK_A0_1) | Bob recv `CK_A0` |
| **B1** | Bob | DHB0, 0, 0 | symmetric step on CK_B0 (Bob already holds DHB0 from A1's ratchet) | MK_B1 = kdf_ck(CK_B0) → CK_B0_1 | Bob send `CK_B0` |
| | Alice recv B1 | | **DH ratchet** (DHr SPK_B→DHB0): RK1→RK2 gives CKr=CK_B0; RK2→RK3 gives CKs=CK_A1; new DHs=DHA1; PN=2 | MK_B1 = kdf_ck(CK_B0) | Alice recv `CK_B0` **=** Bob send `CK_B0` |
| **B2** | Bob | DHB0, 1, 0 | symmetric step | MK_B2 = kdf_ck(CK_B0_1) → CK_B0_2 | same chain `CK_B0` |
| | Alice recv B2 | | no ratchet | MK_B2 = kdf_ck(CK_B0_1) | Alice recv `CK_B0` |
| **A3** | Alice | DHA1, 0, **2** | symmetric step on CK_A1 (DHA1 from B1's ratchet); pn=2 = prior chain A0 length | MK_A3 = kdf_ck(CK_A1) → CK_A1_1 | Alice send `CK_A1` |
| | Bob recv A3 | | **DH ratchet** (DHr DHA0→DHA1): skip pn=2 (already at Nr=2, no skip); RK2→RK3 gives CKr=CK_A1; RK3→RK4 gives CKs=CK_B1; new DHs=DHB1 | MK_A3 = kdf_ck(CK_A1) | Bob recv `CK_A1` **=** Alice send `CK_A1` |
| **B3** | Bob | DHB1, 0, **2** | symmetric step on CK_B1 (DHB1 from A3's ratchet); pn=2 = prior chain B0 length | MK_B3 = kdf_ck(CK_B1) → CK_B1_1 | Bob send `CK_B1` (= Alice recv `CK_B1` when she polls) |

## What the drawing must show (assignment checklist)
1. **DH key pairs & public-key changes:** DHA0 → DHA1 for Alice; SPK_B → DHB0 → DHB1 for
   Bob. Show the public key travelling in each header.
2. **RK before/after each DH ratchet:** the RK0→RK4 spine, each step labelled with its
   `DH(...)` input.
3. **CKs / CKr per side:** CK_A0, CK_A1 (Alice send = Bob recv); CK_B0, CK_B1 (Bob send =
   Alice recv). Show symmetric advances CK_x → CK_x_1 → CK_x_2.
4. **MK per message:** MK_A1, MK_A2, MK_B1, MK_B2, MK_A3, MK_B3.
5. **DH ratchet vs symmetric step:** A1(recv), B1(recv), A3(recv) are DH ratchets; all
   sends and A2/B2 recvs are symmetric steps.
6. **Chain correspondence arrows:** draw a dashed link for each "=" in the last column.

## Layout suggestion
Two vertical lanes (Alice | Bob). Put the shared RK spine down the middle. Draw each
message as a horizontal arrow between lanes, annotated with its header `(dh, n, pn)` and
the MK it produces. Dashed horizontal links connect a sender's chain key to the matching
receiver chain key.
