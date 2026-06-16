//! `comms-release` — reproducibility-gated release manifest + Ed25519 signing
//! (COMMS-S4 WP-4.7, `PLANSET/07` §1.1).
//!
//! A `release.manifest.toml` records, per shipped artifact, its SHA-256, plus the
//! version and git rev. The manifest is then signed with a detached Ed25519 signature
//! over the canonical *unsigned* bytes. The build step is bound to the two-machine
//! reproducibility gate by `--expect`: the manifest builder **refuses** to write a
//! manifest whose staged binary hashes differently from the gated hash, so the shipped
//! binary provably *is* the reproducibility-gated binary.
//!
//! Soft-key signing (a key from CI secrets) marks a bundle "pre-release / not for
//! production"; the HSM swap-in keeps the **same wire form** (only the producer changes) —
//! see `docs/audit/HSM_SEAM.md`.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One shipped file and its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Path relative to the staging root (e.g. `bin/comms-relay`).
    pub path: String,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
}

/// The detached signature block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Always `ed25519`.
    pub algorithm: String,
    /// Lowercase hex of the 32-byte verifying key.
    pub public_key: String,
    /// Lowercase hex of the 64-byte signature over [`Manifest::signing_bytes`].
    pub signature: String,
}

/// The release manifest. Serialized to `release.manifest.toml`. The `signature` block is
/// absent until [`sign`](Manifest::sign) is called and is excluded from the signed bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub git_rev: String,
    /// Serialized as repeated `[[artifact]]` tables. Order is preserved (and is part of
    /// the signed bytes), so keep the staging walk deterministic.
    #[serde(default, rename = "artifact")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

impl Manifest {
    /// Build a manifest by hashing every regular file under `staging`, recording paths
    /// relative to it (forward-slashed, sorted for determinism). `expect` is a set of
    /// `(relative_path, expected_sha256)` the gate must satisfy: if a named artifact is
    /// missing or hashes differently, this fails — binding the manifest to the
    /// reproducibility gate.
    pub fn build(
        version: &str,
        git_rev: &str,
        staging: &Path,
        expect: &[(String, String)],
    ) -> Result<Self, ReleaseError> {
        let mut files = Vec::new();
        collect_files(staging, staging, &mut files)?;
        files.sort();

        let mut artifacts = Vec::with_capacity(files.len());
        for rel in &files {
            let bytes = std::fs::read(staging.join(rel)).map_err(ReleaseError::Io)?;
            artifacts.push(Artifact { path: rel.clone(), sha256: sha256_hex(&bytes) });
        }

        let manifest = Manifest {
            version: version.to_string(),
            git_rev: git_rev.to_string(),
            artifacts,
            signature: None,
        };

        // Enforce the reproducibility gate.
        for (path, want) in expect {
            let got = manifest
                .artifacts
                .iter()
                .find(|a| &a.path == path)
                .ok_or_else(|| ReleaseError::ExpectMissing(path.clone()))?;
            if !got.sha256.eq_ignore_ascii_case(want) {
                return Err(ReleaseError::ExpectMismatch {
                    path: path.clone(),
                    want: want.clone(),
                    got: got.sha256.clone(),
                });
            }
        }
        Ok(manifest)
    }

    /// The canonical bytes that are signed: the manifest TOML with the signature block
    /// omitted. Deterministic (serde struct order + sorted artifacts).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        let unsigned = Manifest { signature: None, ..self.clone() };
        Ok(toml::to_string(&unsigned).map_err(|e| ReleaseError::Toml(e.to_string()))?.into_bytes())
    }

    /// Attach an Ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ReleaseError> {
        let msg = self.signing_bytes()?;
        let sig = key.sign(&msg);
        self.signature = Some(SignatureBlock {
            algorithm: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify the manifest's signature against the public key embedded in it. Returns the
    /// verifying key on success so callers can pin it.
    pub fn verify(&self) -> Result<VerifyingKey, ReleaseError> {
        let block = self.signature.as_ref().ok_or(ReleaseError::Unsigned)?;
        if block.algorithm != "ed25519" {
            return Err(ReleaseError::BadAlgorithm(block.algorithm.clone()));
        }
        let pk_bytes: [u8; 32] = hex::decode(&block.public_key)
            .map_err(|_| ReleaseError::BadHex)?
            .as_slice()
            .try_into()
            .map_err(|_| ReleaseError::BadHex)?;
        let sig_bytes: [u8; 64] = hex::decode(&block.signature)
            .map_err(|_| ReleaseError::BadHex)?
            .as_slice()
            .try_into()
            .map_err(|_| ReleaseError::BadHex)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| ReleaseError::BadKey)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = self.signing_bytes()?;
        vk.verify(&msg, &sig).map_err(|_| ReleaseError::BadSignature)?;
        Ok(vk)
    }

    pub fn to_toml(&self) -> Result<String, ReleaseError> {
        toml::to_string(self).map_err(|e| ReleaseError::Toml(e.to_string()))
    }

    pub fn from_toml(s: &str) -> Result<Self, ReleaseError> {
        toml::from_str(s).map_err(|e| ReleaseError::Toml(e.to_string()))
    }
}

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Recursively collect regular files under `root`, as forward-slashed paths relative to
/// `base`.
fn collect_files(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), ReleaseError> {
    for entry in std::fs::read_dir(dir).map_err(ReleaseError::Io)? {
        let entry = entry.map_err(ReleaseError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, out)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(base).map_err(|_| ReleaseError::Path)?;
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),
    #[error("path is not under the staging root")]
    Path,
    #[error("toml error: {0}")]
    Toml(String),
    #[error("expected artifact `{0}` not found in the staging tree")]
    ExpectMissing(String),
    #[error("reproducibility gate failed for `{path}`: expected {want}, staged {got}")]
    ExpectMismatch { path: String, want: String, got: String },
    #[error("manifest is unsigned")]
    Unsigned,
    #[error("unsupported signature algorithm `{0}`")]
    BadAlgorithm(String),
    #[error("malformed hex in signature block")]
    BadHex,
    #[error("invalid public key")]
    BadKey,
    #[error("signature verification failed")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn staging_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, bytes) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        dir
    }

    #[test]
    fn build_hashes_files_and_is_deterministic() {
        let dir = staging_with(&[("bin/comms-relay", b"RELAY"), ("sbom/x.json", b"{}")]);
        let m1 = Manifest::build("v0.1.0", "abc", dir.path(), &[]).unwrap();
        let m2 = Manifest::build("v0.1.0", "abc", dir.path(), &[]).unwrap();
        assert_eq!(m1, m2, "same tree → same manifest");
        // Sorted, both files present, correct hashes.
        assert_eq!(m1.artifacts[0].path, "bin/comms-relay");
        assert_eq!(m1.artifacts[0].sha256, sha256_hex(b"RELAY"));
        assert_eq!(m1.artifacts.len(), 2);
    }

    #[test]
    fn expect_gate_binds_to_the_reproducibility_hash() {
        let dir = staging_with(&[("bin/comms-relay", b"RELAY")]);
        let good = sha256_hex(b"RELAY");
        // Matching hash → ok.
        assert!(Manifest::build("v1", "g", dir.path(), &[("bin/comms-relay".into(), good.clone())]).is_ok());
        // Wrong hash → fails closed (the staged binary isn't the gated one).
        let err = Manifest::build("v1", "g", dir.path(), &[("bin/comms-relay".into(), "dead".into())]).unwrap_err();
        assert!(matches!(err, ReleaseError::ExpectMismatch { .. }));
        // Missing artifact → fails.
        let err = Manifest::build("v1", "g", dir.path(), &[("bin/ghost".into(), good)]).unwrap_err();
        assert!(matches!(err, ReleaseError::ExpectMissing(_)));
    }

    #[test]
    fn sign_then_verify_roundtrips_and_detects_tampering() {
        let dir = staging_with(&[("bin/comms-relay", b"RELAY"), ("bin/citrate-comms", b"CLIENT")]);
        let mut m = Manifest::build("v0.1.0", "abc123", dir.path(), &[]).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        m.sign(&key).unwrap();
        let vk = m.verify().expect("valid signature verifies");
        assert_eq!(vk.to_bytes(), key.verifying_key().to_bytes());

        // Round-trip through TOML preserves verifiability.
        let restored = Manifest::from_toml(&m.to_toml().unwrap()).unwrap();
        assert!(restored.verify().is_ok());

        // Tamper with an artifact hash → signature no longer matches.
        let mut tampered = restored.clone();
        tampered.artifacts[0].sha256 = sha256_hex(b"EVIL");
        assert!(matches!(tampered.verify(), Err(ReleaseError::BadSignature)));

        // An unsigned manifest does not verify.
        let mut unsigned = m.clone();
        unsigned.signature = None;
        assert!(matches!(unsigned.verify(), Err(ReleaseError::Unsigned)));
    }
}
