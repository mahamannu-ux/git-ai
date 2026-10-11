//! Managed exact-release execution for Task9d.
//!
//! This is the only managed consumer of [`super::authorize_desired_release`].
//! Execution starts solely from a successful [`super::DesiredReleaseAuthorization`]
//! for a retained configuration ID and epoch. The executor fetches `SHA256SUMS`
//! only from the authorization's exact `manifest_url`, requires its bytes to hash
//! to the pinned `manifest_sha256` before parsing, then fetches the platform
//! install script only from the exact-tag GitHub release path and verifies it
//! against the pinned manifest before running it with the exact authorized tag.
//!
//! Channel names, `/worker/releases` endpoints and `/releases/latest/` URLs are
//! never consulted here. The existing interactive `git-ai upgrade` contract is
//! untouched; this module shares its checksum parsing and installer runner.
//!
//! Production uses [`super::UnavailableVerifier`] until Task15 lands, so no
//! managed release can execute in production yet. Unit-test fake verifiers,
//! downloaders and runners are engineering evidence only and are not production
//! verification.

use super::{
    BootstrapRepositories, ConfigurationVerifier, DesiredReleaseAuthorization,
    ReleaseAuthorizationDenial, authorize_desired_release,
};
use chrono::{DateTime, Utc};
use std::path::Path;

/// Failures of managed exact-release execution. Variants carry no URLs,
/// digests, credentials or file bytes so they are safe to log and report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedUpdateError {
    DownloadFailed,
    ManifestDigestMismatch,
    ManifestNotUtf8,
    MissingAssetChecksum,
    AssetDigestMismatch,
    UnexpectedTagOrUrl,
    InstallFailed,
    RestartFailed,
}

impl std::fmt::Display for ManagedUpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::DownloadFailed => "managed_download_failed",
            Self::ManifestDigestMismatch => "managed_manifest_digest_mismatch",
            Self::ManifestNotUtf8 => "managed_manifest_not_utf8",
            Self::MissingAssetChecksum => "managed_missing_asset_checksum",
            Self::AssetDigestMismatch => "managed_asset_digest_mismatch",
            Self::UnexpectedTagOrUrl => "managed_unexpected_tag_or_url",
            Self::InstallFailed => "managed_install_failed",
            Self::RestartFailed => "managed_restart_failed",
        };
        formatter.write_str(code)
    }
}

/// Outcome of running an authorized release. A desired release equal to the
/// running version is a no-op; any other authorized version installs, whether
/// it moves forward or backward (rollback installs the retained older tuple).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedUpdateOutcome {
    NoopAlreadyAtVersion,
    Updated { version: String, tag: String },
}

/// Outcome of the authorize-then-execute entry point. Authorization denials are
/// safe failures: local evidence and authorization state are untouched and the
/// operation stays retryable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedApplyOutcome {
    SkippedNotAuthorized { denial: ReleaseAuthorizationDenial },
    NoopAlreadyAtVersion,
    Updated { version: String, tag: String },
}

/// Dependency-injected side effects so unit tests run network-free.
pub trait ManagedUpdateDeps {
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError>;
    fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError>;
    fn restart_daemon(&self) -> Result<(), ManagedUpdateError>;
}

/// Production side effects: direct HTTPS fetch, the shared verified installer
/// runner, and the existing bounded daemon restart.
pub struct ProductionManagedUpdateDeps;

impl ManagedUpdateDeps for ProductionManagedUpdateDeps {
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError> {
        let (_agent, request) = crate::api::client::ApiContext::http_get(url, Some(30));
        let response =
            crate::http::send(request).map_err(|_| ManagedUpdateError::DownloadFailed)?;
        if response.status_code != 200 {
            return Err(ManagedUpdateError::DownloadFailed);
        }
        Ok(response.as_bytes().to_vec())
    }

    fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError> {
        crate::commands::upgrade::run_install_script(script, tag, true)
            .map_err(|_| ManagedUpdateError::InstallFailed)
    }

    fn restart_daemon(&self) -> Result<(), ManagedUpdateError> {
        let config = crate::daemon::DaemonConfig::from_env_or_default_paths()
            .map_err(|_| ManagedUpdateError::RestartFailed)?;
        crate::commands::daemon::restart_daemon(&config)
            .map_err(|_| ManagedUpdateError::RestartFailed)
    }
}

fn expected_manifest_url(release_tag: &str) -> String {
    format!("https://github.com/mahamannu-ux/git-ai/releases/download/{release_tag}/SHA256SUMS")
}

fn platform_script_name() -> &'static str {
    #[cfg(windows)]
    {
        "install.ps1"
    }
    #[cfg(not(windows))]
    {
        "install.sh"
    }
}

/// Execute one already-authorized exact release. Performs zero network,
/// installer or restart calls when the desired version equals the running
/// version. Never passes credentials; only the exact authorized tag reaches
/// the installer, via the existing `GIT_AI_RELEASE_TAG` seam.
pub fn execute_authorized_release(
    authorization: &DesiredReleaseAuthorization,
    current_version: &str,
    deps: &dyn ManagedUpdateDeps,
) -> Result<ManagedUpdateOutcome, ManagedUpdateError> {
    let release = &authorization.desired_release;
    if release.version == current_version {
        return Ok(ManagedUpdateOutcome::NoopAlreadyAtVersion);
    }
    if release.manifest_url != expected_manifest_url(&release.release_tag) {
        return Err(ManagedUpdateError::UnexpectedTagOrUrl);
    }
    let manifest_bytes = deps.fetch_bytes(&release.manifest_url)?;
    crate::commands::upgrade::verify_sha256(&manifest_bytes, &release.manifest_sha256)
        .map_err(|_| ManagedUpdateError::ManifestDigestMismatch)?;
    let manifest =
        String::from_utf8(manifest_bytes).map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    let checksums = crate::commands::upgrade::parse_checksums(&manifest);
    let script_name = platform_script_name();
    let expected_asset = checksums
        .get(script_name)
        .ok_or(ManagedUpdateError::MissingAssetChecksum)?;
    let asset_url = format!(
        "https://github.com/mahamannu-ux/git-ai/releases/download/{}/{}",
        release.release_tag, script_name
    );
    let asset_bytes = deps.fetch_bytes(&asset_url)?;
    crate::commands::upgrade::verify_sha256(&asset_bytes, expected_asset)
        .map_err(|_| ManagedUpdateError::AssetDigestMismatch)?;
    let script =
        std::str::from_utf8(&asset_bytes).map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    deps.run_installer(script, &release.release_tag)?;
    deps.restart_daemon()?;
    Ok(ManagedUpdateOutcome::Updated {
        version: release.version.clone(),
        tag: release.release_tag.clone(),
    })
}

/// Authorize one retained configuration and execute its exact release.
/// Every denial returns a safe skip with zero lifecycle side effects.
#[allow(clippy::too_many_arguments)]
pub fn authorize_and_apply(
    state_path: &Path,
    configuration_id: &str,
    epoch: u64,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    current_version: &str,
    deps: &dyn ManagedUpdateDeps,
) -> Result<ManagedApplyOutcome, ManagedUpdateError> {
    let authorization = match authorize_desired_release(
        state_path,
        configuration_id,
        epoch,
        now,
        client_version,
        bootstrap,
        verifier,
    ) {
        Ok(authorization) => authorization,
        Err(denial) => return Ok(ManagedApplyOutcome::SkippedNotAuthorized { denial }),
    };
    match execute_authorized_release(&authorization, current_version, deps)? {
        ManagedUpdateOutcome::NoopAlreadyAtVersion => Ok(ManagedApplyOutcome::NoopAlreadyAtVersion),
        ManagedUpdateOutcome::Updated { version, tag } => {
            Ok(ManagedApplyOutcome::Updated { version, tag })
        }
    }
}

/// Apply the retained active configuration's exact release, if any. Rollback
/// needs no special path: reassigning the retained older configuration makes
/// it active, and this same function then installs its own tuple (which may be
/// older than the running version).
pub fn apply_retained_release(
    state_path: &Path,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    current_version: &str,
    deps: &dyn ManagedUpdateDeps,
) -> Result<ManagedApplyOutcome, ManagedUpdateError> {
    let state = super::load_state(state_path).map_err(|_| ManagedUpdateError::DownloadFailed)?;
    let active = match state.active.as_ref() {
        Some(active) => active,
        None => {
            return Ok(ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            });
        }
    };
    authorize_and_apply(
        state_path,
        active.envelope.configuration_id(),
        active.envelope.epoch(),
        now,
        client_version,
        bootstrap,
        verifier,
        current_version,
        deps,
    )
}

#[cfg(test)]
mod tests {
    use super::super::{
        ConfigurationVerifier, VerificationMetadata, VerificationResult, process_configuration,
    };
    use super::*;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::HashSet;

    /// Fake side effects for engineering-evidence unit tests only. This is not
    /// production verification: production uses `UnavailableVerifier` and
    /// performs zero lifecycle side effects.
    struct FakeDeps {
        manifest: Result<Vec<u8>, ManagedUpdateError>,
        asset: Result<Vec<u8>, ManagedUpdateError>,
        install: Result<(), ManagedUpdateError>,
        restart: Result<(), ManagedUpdateError>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeDeps {
        fn success(manifest: Vec<u8>, asset: Vec<u8>) -> Self {
            Self {
                manifest: Ok(manifest),
                asset: Ok(asset),
                install: Ok(()),
                restart: Ok(()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl ManagedUpdateDeps for FakeDeps {
        fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError> {
            self.calls.borrow_mut().push(format!("fetch"));
            let _ = url;
            if url.ends_with("SHA256SUMS") {
                self.manifest.clone()
            } else {
                self.asset.clone()
            }
        }

        fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError> {
            self.calls
                .borrow_mut()
                .push(format!("install tag={tag} bytes={}", script.len()));
            self.install.clone()
        }

        fn restart_daemon(&self) -> Result<(), ManagedUpdateError> {
            self.calls.borrow_mut().push("restart".to_string());
            self.restart.clone()
        }
    }

    /// URL-asserting fake: records every fetched URL for exact-path tests.
    struct UrlRecordingDeps {
        manifest: Vec<u8>,
        asset: Vec<u8>,
        install_tag: RefCell<Option<String>>,
        urls: RefCell<Vec<String>>,
        restarts: RefCell<u32>,
    }

    impl ManagedUpdateDeps for UrlRecordingDeps {
        fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError> {
            self.urls.borrow_mut().push(url.to_string());
            if url.ends_with("SHA256SUMS") {
                Ok(self.manifest.clone())
            } else {
                Ok(self.asset.clone())
            }
        }

        fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError> {
            assert!(!script.is_empty());
            *self.install_tag.borrow_mut() = Some(tag.to_string());
            Ok(())
        }

        fn restart_daemon(&self) -> Result<(), ManagedUpdateError> {
            *self.restarts.borrow_mut() += 1;
            Ok(())
        }
    }

    struct Repositories(HashSet<String>);
    impl BootstrapRepositories for Repositories {
        fn contains_repository_id(&self, repository_id: &str) -> bool {
            self.0.contains(repository_id)
        }
        fn repository_count(&self) -> usize {
            self.0.len()
        }
    }
    struct Verifier(VerificationResult);
    impl ConfigurationVerifier for Verifier {
        fn verify(&self, _: &[u8], _: &VerificationMetadata) -> VerificationResult {
            self.0
        }
    }

    fn repositories() -> Repositories {
        Repositories(HashSet::from([
            "11111111-1111-4111-8111-111111111111".to_string()
        ]))
    }

    fn sha_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn v2_config(id: &str, epoch: u64, version: &str, tag: &str, manifest_sha: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":2,"configurationId":"{id}","epoch":{epoch},"issuedAt":"2026-10-10T00:00:00Z","validUntil":"2026-10-12T00:00:00Z","clientCompatibility":{{"minimumVersion":"1.6.18","maximumVersion":"1.6.20"}},"desiredRelease":{{"version":"{version}","releaseTag":"{tag}","manifestUrl":"https://github.com/mahamannu-ux/git-ai/releases/download/{tag}/SHA256SUMS","manifestSha256":"{manifest_sha}"}},"channel":"enterprise-latest","ring":null,"repositoryPolicies":[{{"repositoryId":"11111111-1111-4111-8111-111111111111","enrollmentId":"22222222-2222-4222-8222-222222222222","grantId":"33333333-3333-4333-8333-333333333333","branchPatterns":["main"],"effectiveFrom":"2026-10-10T00:00:00Z","effectiveUntil":null}}],"securityActivation":{{"mode":"monitor","version":1}},"verification":{{"required":true,"state":"unavailable"}}}}"#).into_bytes()
    }

    fn v1_config(id: &str, epoch: u64) -> Vec<u8> {
        format!(r#"{{"schemaVersion":1,"configurationId":"{id}","epoch":{epoch},"issuedAt":"2026-10-10T00:00:00Z","validUntil":"2026-10-12T00:00:00Z","targetClientVersion":"1.6.19","channel":"latest","ring":null,"repositoryPolicies":[{{"repositoryId":"11111111-1111-4111-8111-111111111111","enrollmentId":"22222222-2222-4222-8222-222222222222","grantId":"33333333-3333-4333-8333-333333333333","branchPatterns":["main"],"effectiveFrom":"2026-10-10T00:00:00Z","effectiveUntil":null}}],"securityActivation":{{"mode":"monitor","version":1}},"verification":{{"required":true,"state":"unavailable"}}}}"#).into_bytes()
    }

    fn persist(path: &Path, raw: &[u8]) {
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let outcome = process_configuration(
            raw,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            path,
        );
        assert_eq!(outcome.result, super::super::AcknowledgementResult::Applied);
    }

    fn auth_for_test(version: &str, tag: &str, manifest_sha: &str) -> DesiredReleaseAuthorization {
        DesiredReleaseAuthorization {
            configuration_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
            epoch: 1,
            desired_release: super::super::DesiredRelease {
                version: version.to_string(),
                release_tag: tag.to_string(),
                manifest_url: format!(
                    "https://github.com/mahamannu-ux/git-ai/releases/download/{tag}/SHA256SUMS"
                ),
                manifest_sha256: manifest_sha.to_string(),
            },
        }
    }

    #[test]
    fn no_authorization_means_zero_lifecycle_calls() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let deps = FakeDeps::success(b"manifest".to_vec(), b"asset".to_vec());
        let outcome = authorize_and_apply(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            "1.6.19",
            &deps,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            }
        );
        assert!(deps.calls.borrow().is_empty());

        let retained = apply_retained_release(
            &path,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            "1.6.19",
            &deps,
        )
        .unwrap();
        assert_eq!(
            retained,
            ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            }
        );
        assert!(deps.calls.borrow().is_empty());
    }

    #[test]
    fn production_unavailable_verifier_means_zero_lifecycle_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let manifest = b"deadbeef  install.sh\n".to_vec();
        let candidate = v2_config(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "9.8.7",
            "v9.8.7",
            &sha_hex(&manifest),
        );
        persist(&path, &candidate);
        let before = std::fs::read(&path).unwrap();

        let deps = FakeDeps::success(manifest, b"script".to_vec());
        let outcome = authorize_and_apply(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            &super::super::UnavailableVerifier,
            "1.6.19",
            &deps,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::VerificationUnavailable,
            }
        );
        assert!(deps.calls.borrow().is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn v1_and_legacy_state_cannot_execute_a_release() {
        let temp = tempfile::tempdir().unwrap();
        let now = "2026-10-10T01:00:00Z".parse().unwrap();

        let v1_path = temp.path().join("fleet/v1.json");
        persist(
            &v1_path,
            &v1_config("dddddddd-dddd-4ddd-8ddd-dddddddddddd", 1),
        );
        let deps = FakeDeps::success(b"m".to_vec(), b"a".to_vec());
        assert_eq!(
            authorize_and_apply(
                &v1_path,
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
                "1.6.19",
                &deps,
            )
            .unwrap(),
            ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::SchemaV1,
            }
        );
        assert!(deps.calls.borrow().is_empty());

        let legacy_path = temp.path().join("fleet/legacy.json");
        let candidate = v2_config(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "9.8.7",
            "v9.8.7",
            &"a".repeat(64),
        );
        persist(&legacy_path, &candidate);
        let mut state = super::super::load_state(&legacy_path).unwrap();
        state.active.as_mut().unwrap().exact_json = None;
        super::super::atomic_write_json(&legacy_path, &state).unwrap();
        assert_eq!(
            authorize_and_apply(
                &legacy_path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
                "1.6.19",
                &deps,
            )
            .unwrap(),
            ManagedApplyOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::MissingExactJson,
            }
        );
        assert!(deps.calls.borrow().is_empty());
    }

    #[test]
    fn exact_authorized_release_uses_pinned_manifest_and_exact_tag_assets() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let deps = UrlRecordingDeps {
            manifest: manifest.clone(),
            asset: asset.clone(),
            install_tag: RefCell::new(None),
            urls: RefCell::new(Vec::new()),
            restarts: RefCell::new(0),
        };
        let outcome = execute_authorized_release(&auth, "1.6.19", &deps).unwrap();
        assert_eq!(
            outcome,
            ManagedUpdateOutcome::Updated {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );
        assert_eq!(
            *deps.urls.borrow(),
            vec![
                "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS"
                    .to_string(),
                format!(
                    "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/{}",
                    platform_script_name()
                ),
            ]
        );
        assert_eq!(*deps.install_tag.borrow(), Some("v9.8.7".to_string()));
        assert_eq!(*deps.restarts.borrow(), 1);
        for url in deps.urls.borrow().iter() {
            assert!(!url.contains("/worker/releases"));
            assert!(!url.contains("latest"));
        }
    }

    #[test]
    fn manifest_digest_mismatch_missing_asset_and_asset_mismatch_fail_closed() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();

        // Digest mismatch: no asset fetch, install or restart.
        let auth = auth_for_test("9.8.7", "v9.8.7", &"b".repeat(64));
        let deps = FakeDeps::success(b"tampered manifest".to_vec(), asset.clone());
        assert_eq!(
            execute_authorized_release(&auth, "1.6.19", &deps),
            Err(ManagedUpdateError::ManifestDigestMismatch)
        );
        assert_eq!(*deps.calls.borrow(), vec!["fetch".to_string()]);

        // Missing asset checksum: manifest verifies but pins nothing usable.
        let manifest = format!("{}  other.bin\n", sha_hex(&asset)).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let deps = FakeDeps::success(manifest, asset.clone());
        assert_eq!(
            execute_authorized_release(&auth, "1.6.19", &deps),
            Err(ManagedUpdateError::MissingAssetChecksum)
        );
        assert_eq!(*deps.calls.borrow(), vec!["fetch".to_string()]);

        // Asset mismatch: installer and restart never run.
        let manifest = format!("{}  {}\n", "c".repeat(64), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let deps = FakeDeps::success(manifest, asset.clone());
        assert_eq!(
            execute_authorized_release(&auth, "1.6.19", &deps),
            Err(ManagedUpdateError::AssetDigestMismatch)
        );
        assert_eq!(
            *deps.calls.borrow(),
            vec!["fetch".to_string(), "fetch".to_string()]
        );

        // Download failure: nothing else runs.
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let deps = FakeDeps {
            manifest: Err(ManagedUpdateError::DownloadFailed),
            asset: Ok(asset),
            install: Ok(()),
            restart: Ok(()),
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            execute_authorized_release(&auth, "1.6.19", &deps),
            Err(ManagedUpdateError::DownloadFailed)
        );
        assert_eq!(*deps.calls.borrow(), vec!["fetch".to_string()]);
    }

    #[test]
    fn wrong_tag_or_url_fails_closed_before_any_fetch() {
        let manifest = b"anything\n".to_vec();
        let mut auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        auth.desired_release.manifest_url =
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.6/SHA256SUMS"
                .to_string();
        let deps = FakeDeps::success(manifest, b"asset".to_vec());
        assert_eq!(
            execute_authorized_release(&auth, "1.6.19", &deps),
            Err(ManagedUpdateError::UnexpectedTagOrUrl)
        );
        assert!(deps.calls.borrow().is_empty());
    }

    #[test]
    fn retained_previous_uses_its_own_tuple_and_can_install_older_version() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();

        let old_asset = b"#!/bin/sh\necho old\n".to_vec();
        let old_manifest =
            format!("{}  {}\n", sha_hex(&old_asset), platform_script_name()).into_bytes();
        let previous = v2_config(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "9.8.6",
            "v9.8.6",
            &sha_hex(&old_manifest),
        );
        let new_asset = b"#!/bin/sh\necho new\n".to_vec();
        let new_manifest =
            format!("{}  {}\n", sha_hex(&new_asset), platform_script_name()).into_bytes();
        let active = v2_config(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            2,
            "9.8.7",
            "v9.8.7",
            &sha_hex(&new_manifest),
        );
        persist(&path, &previous);
        persist(&path, &active);

        // Rollback reassignment targets the retained N-1 tuple, whose own
        // manifest URL and digest install the older version.
        let deps = UrlRecordingDeps {
            manifest: old_manifest,
            asset: old_asset,
            install_tag: RefCell::new(None),
            urls: RefCell::new(Vec::new()),
            restarts: RefCell::new(0),
        };
        let outcome = authorize_and_apply(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            "9.8.7",
            &deps,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ManagedApplyOutcome::Updated {
                version: "9.8.6".to_string(),
                tag: "v9.8.6".to_string(),
            }
        );
        assert!(
            deps.urls
                .borrow()
                .iter()
                .all(|url| url.contains("/v9.8.6/"))
        );
        assert_eq!(*deps.install_tag.borrow(), Some("v9.8.6".to_string()));
    }

    #[test]
    fn equal_version_is_a_noop_with_zero_calls() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let deps = FakeDeps::success(manifest, asset);
        assert_eq!(
            execute_authorized_release(&auth, "9.8.7", &deps),
            Ok(ManagedUpdateOutcome::NoopAlreadyAtVersion)
        );
        assert!(deps.calls.borrow().is_empty());
    }

    #[test]
    fn failed_update_preserves_state_and_stays_retryable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let candidate = v2_config(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "9.8.7",
            "v9.8.7",
            &sha_hex(&manifest),
        );
        persist(&path, &candidate);
        let before = std::fs::read(&path).unwrap();

        let failing = FakeDeps {
            manifest: Ok(manifest.clone()),
            asset: Ok(asset.clone()),
            install: Err(ManagedUpdateError::InstallFailed),
            restart: Ok(()),
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            authorize_and_apply(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
                "1.6.19",
                &failing,
            ),
            Err(ManagedUpdateError::InstallFailed)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let retry = FakeDeps::success(manifest, asset);
        assert_eq!(
            authorize_and_apply(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
                "1.6.19",
                &retry,
            )
            .unwrap(),
            ManagedApplyOutcome::Updated {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );
    }

    #[test]
    fn failure_reports_carry_no_secrets() {
        for error in [
            ManagedUpdateError::DownloadFailed,
            ManagedUpdateError::ManifestDigestMismatch,
            ManagedUpdateError::ManifestNotUtf8,
            ManagedUpdateError::MissingAssetChecksum,
            ManagedUpdateError::AssetDigestMismatch,
            ManagedUpdateError::UnexpectedTagOrUrl,
            ManagedUpdateError::InstallFailed,
            ManagedUpdateError::RestartFailed,
        ] {
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("trk_v1"));
            assert!(!rendered.contains("aaaaaaa"));
            assert!(!rendered.contains("github.com"));
        }
    }
}
