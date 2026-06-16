# Release signing: the HSM swap-in seam

The release manifest (`release.manifest.toml`) carries a detached **Ed25519** signature
over its canonical unsigned bytes (per-artifact SHA-256 + version + git rev). See
`crates/comms-release` and `.github/workflows/release.yml` (COMMS-S4 WP-4.7).

## Two signing postures, one wire form

The signature's **wire form never changes** — `algorithm = "ed25519"`, a 32-byte public
key, a 64-byte signature. Only the **producer** of those bytes changes:

| Posture | Producer | Marking |
|---|---|---|
| **Soft-key (today)** | `sign-manifest` reads `RELEASE_SIGNING_KEY_HEX` (a 32-byte Ed25519 seed) from CI secrets and signs in-process. | Bundle is **"pre-release / not for production."** |
| **HSM (production)** | An HSM / KMS holding the Ed25519 private key signs `Manifest::signing_bytes()`; the producer only ever sees the public key + the returned signature. | Production. |

Because verification is identical either way (`Manifest::verify()` checks the embedded
public key against the signed bytes), consumers — the airgap installer, an auditor —
need no change when the swap happens. **Pin the production public key** out of band and
reject any manifest signed by a different key.

## Swapping in an HSM

1. Provision the Ed25519 key in the HSM/KMS (e.g. YubiHSM, AWS KMS Ed25519, GCP KMS).
2. Replace the `sign-manifest` step in `release.yml` with a call that:
   - reads `release-staging/release.manifest.toml`,
   - extracts `Manifest::signing_bytes()` (the TOML with the `[signature]` block omitted),
   - asks the HSM to sign those bytes,
   - writes back the `[signature]` block with the HSM's public key + signature.
   The `comms-release` library already exposes `signing_bytes()` for exactly this; only
   the in-process `key.sign()` call is replaced by the HSM round trip.
3. Update the pinned production public key in the install/verify procedure
   (`docs/audit/AIRGAP_TEST.md`) and in the Tier-1 audit packet.

## Do not
- Do **not** keep the soft key after the HSM lands — rotate it out and remove the secret.
- Do **not** widen verification to "any key in the manifest is fine"; verification must be
  against the **pinned** production key, or the signature proves only self-consistency.
