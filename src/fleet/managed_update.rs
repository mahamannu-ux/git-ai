//! Managed exact-release staging and post-shutdown installation for Task9d.
//!
//! This is the only managed consumer of [`super::authorize_desired_release`].
//! Execution is split across the existing graceful daemon-update lifecycle so
//! the running daemon never installs or restarts itself:
//!
//! 1. **Stage (pre-shutdown).** Telemetry authorizes the retained active
//!    configuration, fetches `SHA256SUMS` only from the authorization's exact
//!    `manifest_url`, requires its bytes to hash to the pinned `manifest_sha256`
//!    before parsing, then fetches the platform install script only from the
//!    exact-tag GitHub release path and verifies it against the pinned manifest.
//!    The verified bundle is staged to disk. No installer runs here.
//! 2. **Request.** Telemetry requests the existing coordinated
//!    `RestartAfterUpdate` path, which drains accepted checkpoints first.
//! 3. **Install (post-shutdown).** `daemon_run_pending_self_update` installs
//!    the staged bundle after the daemon is fully dead, then the normal
//!    lifecycle restarts the daemon. Staging is cleared on success and on
//!    failure, so a failed install can never loop: retry re-stages from the
//!    retained authorization.
//!
//! Channel names, `/worker/releases` endpoints and `/releases/latest/` URLs are
//! never consulted here. The existing interactive `git-ai upgrade` contract is
//! untouched; this module shares its checksum parsing and installer runner.
//!
//! Production uses [`super::UnavailableVerifier`] until Task15 lands, so no
//! managed release can stage or install in production yet. Unit-test fake
//! fetchers/installers are engineering evidence only and are not production
//! verification.

use super::{
    BootstrapRepositories, ConfigurationVerifier, DesiredReleaseAuthorization,
    ReleaseAuthorizationDenial, authorize_desired_release,
};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Staged-bundle directory, relative to `~/.git-ai`.
pub const PENDING_UPDATE_REL: &str = "fleet/pending-update";
const TAG_FILE: &str = "tag";
const VERSION_FILE: &str = "version";
const MANIFEST_SHA_FILE: &str = "manifest.sha256";
const MANIFEST_FILE: &str = "manifest";
const SCRIPT_FILE: &str = "script";
const BINDING_ID_FILE: &str = "config.id";
const BINDING_EPOCH_FILE: &str = "config.epoch";
const MAX_STAGED_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_STAGED_SCRIPT_BYTES: usize = 1024 * 1024;

/// Failures of managed staging/installation. Variants carry no URLs, digests,
/// credentials or file bytes so they are safe to log and report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedUpdateError {
    DownloadFailed,
    ManifestDigestMismatch,
    ManifestNotUtf8,
    MissingAssetChecksum,
    AssetDigestMismatch,
    UnexpectedTagOrUrl,
    StageFailed,
    InstallFailed,
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
            Self::StageFailed => "managed_stage_failed",
            Self::InstallFailed => "managed_install_failed",
        };
        formatter.write_str(code)
    }
}

/// Verified but not yet installed bundle. Bytes are public release assets;
/// `Debug` reports lengths only.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub version: String,
    pub tag: String,
    pub manifest: Vec<u8>,
    pub script: Vec<u8>,
}

impl std::fmt::Debug for VerifiedBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedBundle")
            .field("version", &self.version)
            .field("tag", &self.tag)
            .field("manifest_bytes", &self.manifest.len())
            .field("script_bytes", &self.script.len())
            .finish()
    }
}

/// Outcome of fetching and verifying an authorized release. A desired release
/// equal to the running version is a no-op with zero network calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    NoopAlreadyAtVersion,
    Verified(VerifiedBundle),
}

/// Outcome of the authorize-then-stage entry point. Authorization denials are
/// safe skips with zero side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    SkippedNotAuthorized { denial: ReleaseAuthorizationDenial },
    NoopAlreadyAtVersion,
    Staged { version: String, tag: String },
}

/// Outcome of installing a staged bundle after shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagedInstallOutcome {
    Installed { version: String, tag: String },
    NoStagedBundle,
}

/// Network side effects for staging. Staging code cannot install or restart by
/// construction: this trait exposes only fetching.
pub trait BundleFetch {
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError>;
}

/// Installer side effects for post-shutdown installation.
pub trait BundleInstall {
    fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError>;
}

/// Production fetcher: direct HTTPS fetch.
pub struct ProductionBundleFetch;

impl BundleFetch for ProductionBundleFetch {
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError> {
        let (_agent, request) = crate::api::client::ApiContext::http_get(url, Some(30));
        let response =
            crate::http::send(request).map_err(|_| ManagedUpdateError::DownloadFailed)?;
        if response.status_code != 200 {
            return Err(ManagedUpdateError::DownloadFailed);
        }
        Ok(response.as_bytes().to_vec())
    }
}

/// Production installer: the shared verified installer runner.
pub struct ProductionBundleInstaller;

impl BundleInstall for ProductionBundleInstaller {
    fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError> {
        crate::commands::upgrade::run_install_script(script, tag, true)
            .map_err(|_| ManagedUpdateError::InstallFailed)
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

fn valid_staged_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && !tag.contains("..")
        && tag.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// Fetch and verify one already-authorized exact release. Performs zero network
/// calls when the desired version equals the running version. Never passes
/// credentials; only public release bytes are handled.
pub fn fetch_and_verify_bundle(
    authorization: &DesiredReleaseAuthorization,
    current_version: &str,
    fetch: &dyn BundleFetch,
) -> Result<FetchOutcome, ManagedUpdateError> {
    let release = &authorization.desired_release;
    if release.version == current_version {
        return Ok(FetchOutcome::NoopAlreadyAtVersion);
    }
    if release.manifest_url != expected_manifest_url(&release.release_tag) {
        return Err(ManagedUpdateError::UnexpectedTagOrUrl);
    }
    let manifest_bytes = fetch.fetch_bytes(&release.manifest_url)?;
    if manifest_bytes.len() > MAX_STAGED_MANIFEST_BYTES {
        return Err(ManagedUpdateError::DownloadFailed);
    }
    crate::commands::upgrade::verify_sha256(&manifest_bytes, &release.manifest_sha256)
        .map_err(|_| ManagedUpdateError::ManifestDigestMismatch)?;
    let manifest = String::from_utf8(manifest_bytes.clone())
        .map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    let checksums = crate::commands::upgrade::parse_checksums(&manifest);
    let script_name = platform_script_name();
    let expected_asset = checksums
        .get(script_name)
        .ok_or(ManagedUpdateError::MissingAssetChecksum)?;
    let asset_url = format!(
        "https://github.com/mahamannu-ux/git-ai/releases/download/{}/{}",
        release.release_tag, script_name
    );
    let script_bytes = fetch.fetch_bytes(&asset_url)?;
    if script_bytes.len() > MAX_STAGED_SCRIPT_BYTES {
        return Err(ManagedUpdateError::DownloadFailed);
    }
    crate::commands::upgrade::verify_sha256(&script_bytes, expected_asset)
        .map_err(|_| ManagedUpdateError::AssetDigestMismatch)?;
    let script =
        std::str::from_utf8(&script_bytes).map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    if !valid_staged_tag(&release.release_tag) {
        return Err(ManagedUpdateError::UnexpectedTagOrUrl);
    }
    Ok(FetchOutcome::Verified(VerifiedBundle {
        version: release.version.clone(),
        tag: release.release_tag.clone(),
        manifest: manifest_bytes,
        script: script.as_bytes().to_vec(),
    }))
}

/// Default staging directory (`~/.git-ai/fleet/pending-update/`).
pub fn default_staging_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| staging_dir_for_home(&home))
}

/// Staging directory for an explicit home (used by endpoint cleanup).
pub fn staging_dir_for_home(home: &Path) -> PathBuf {
    home.join(".git-ai").join(PENDING_UPDATE_REL)
}

fn write_staged_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), ManagedUpdateError> {
    std::fs::create_dir_all(dir).map_err(|_| ManagedUpdateError::StageFailed)?;
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(|_| ManagedUpdateError::StageFailed)?;
    std::fs::rename(&temporary, dir.join(name)).map_err(|_| {
        let _ = std::fs::remove_file(&temporary);
        ManagedUpdateError::StageFailed
    })
}

fn read_staged_file(dir: &Path, name: &str, maximum: usize) -> Result<Vec<u8>, ManagedUpdateError> {
    let bytes = std::fs::read(dir.join(name)).map_err(|_| ManagedUpdateError::StageFailed)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ManagedUpdateError::StageFailed);
    }
    Ok(bytes)
}

fn clear_staging_dir(dir: &Path) {
    for name in [
        TAG_FILE,
        VERSION_FILE,
        MANIFEST_SHA_FILE,
        MANIFEST_FILE,
        SCRIPT_FILE,
        BINDING_ID_FILE,
        BINDING_EPOCH_FILE,
    ] {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// Authorization binding recorded alongside staged bytes. A staged bundle may
/// only install while this binding still matches the retained active
/// authorization; anything else is cleared, never installed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedBinding {
    configuration_id: String,
    epoch: u64,
    tag: String,
    version: String,
    manifest_sha256: String,
}

fn read_bounded_string(dir: &Path, name: &str, maximum: usize) -> Option<String> {
    let bytes = std::fs::read(dir.join(name)).ok()?;
    if bytes.is_empty() || bytes.len() > maximum {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn read_staged_binding(dir: &Path) -> Option<StagedBinding> {
    let configuration_id = read_bounded_string(dir, BINDING_ID_FILE, 128)?;
    let epoch = read_bounded_string(dir, BINDING_EPOCH_FILE, 32)?
        .parse::<u64>()
        .ok()?;
    if epoch == 0 {
        return None;
    }
    let tag = read_bounded_string(dir, TAG_FILE, 128)?;
    if !valid_staged_tag(&tag) {
        return None;
    }
    let version = read_bounded_string(dir, VERSION_FILE, 64)?;
    if version.is_empty() {
        return None;
    }
    let manifest_sha256 = read_bounded_string(dir, MANIFEST_SHA_FILE, 128)?;
    if manifest_sha256.len() != 64 {
        return None;
    }
    Some(StagedBinding {
        configuration_id,
        epoch,
        tag,
        version,
        manifest_sha256,
    })
}

fn binding_matches(authorization: &DesiredReleaseAuthorization, binding: &StagedBinding) -> bool {
    binding.configuration_id == authorization.configuration_id
        && binding.epoch == authorization.epoch
        && binding.tag == authorization.desired_release.release_tag
        && binding.version == authorization.desired_release.version
        && binding.manifest_sha256 == authorization.desired_release.manifest_sha256
}

/// Stage a verified bundle for post-shutdown installation. The exact
/// authorized tag travels with the bundle; only it reaches the installer.
pub fn stage_verified_bundle(
    staging_dir: &Path,
    authorization: &DesiredReleaseAuthorization,
    bundle: &VerifiedBundle,
) -> Result<(), ManagedUpdateError> {
    if bundle.version != authorization.desired_release.version
        || bundle.tag != authorization.desired_release.release_tag
        || !valid_staged_tag(&bundle.tag)
        || bundle.version.is_empty()
        || bundle.version.len() > 64
    {
        return Err(ManagedUpdateError::UnexpectedTagOrUrl);
    }
    write_staged_file(staging_dir, TAG_FILE, bundle.tag.as_bytes())?;
    write_staged_file(staging_dir, VERSION_FILE, bundle.version.as_bytes())?;
    write_staged_file(
        staging_dir,
        BINDING_ID_FILE,
        authorization.configuration_id.as_bytes(),
    )?;
    write_staged_file(
        staging_dir,
        BINDING_EPOCH_FILE,
        authorization.epoch.to_string().as_bytes(),
    )?;
    write_staged_file(
        staging_dir,
        MANIFEST_SHA_FILE,
        authorization.desired_release.manifest_sha256.as_bytes(),
    )?;
    write_staged_file(staging_dir, MANIFEST_FILE, &bundle.manifest)?;
    write_staged_file(staging_dir, SCRIPT_FILE, &bundle.script)?;
    Ok(())
}

/// Authorize one retained configuration, verify its exact release and stage it.
/// Skips, no-ops and failures clear any existing staging: a bundle from a
/// superseded authorization must never survive to a later install. When the
/// retained authorization still matches the staged binding byte-for-byte, the
/// existing staging is kept without re-downloading (installation re-verifies
/// the bytes).
#[allow(clippy::too_many_arguments)]
pub fn authorize_and_stage(
    state_path: &Path,
    configuration_id: &str,
    epoch: u64,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    current_version: &str,
    fetch: &dyn BundleFetch,
    staging_dir: &Path,
) -> Result<StageOutcome, ManagedUpdateError> {
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
        Err(denial) => {
            clear_staging_dir(staging_dir);
            return Ok(StageOutcome::SkippedNotAuthorized { denial });
        }
    };
    if authorization.desired_release.version == current_version {
        clear_staging_dir(staging_dir);
        return Ok(StageOutcome::NoopAlreadyAtVersion);
    }
    if let Some(binding) = read_staged_binding(staging_dir)
        && binding_matches(&authorization, &binding)
        && staging_dir.join(MANIFEST_FILE).is_file()
        && staging_dir.join(SCRIPT_FILE).is_file()
    {
        return Ok(StageOutcome::Staged {
            version: binding.version,
            tag: binding.tag,
        });
    }
    match fetch_and_verify_bundle(&authorization, current_version, fetch) {
        Ok(FetchOutcome::NoopAlreadyAtVersion) => {
            clear_staging_dir(staging_dir);
            Ok(StageOutcome::NoopAlreadyAtVersion)
        }
        Ok(FetchOutcome::Verified(bundle)) => {
            let staged = StageOutcome::Staged {
                version: bundle.version.clone(),
                tag: bundle.tag.clone(),
            };
            if let Err(error) = stage_verified_bundle(staging_dir, &authorization, &bundle) {
                clear_staging_dir(staging_dir);
                return Err(error);
            }
            Ok(staged)
        }
        Err(error) => {
            clear_staging_dir(staging_dir);
            Err(error)
        }
    }
}

/// Stage the retained active configuration's exact release, if any. Rollback
/// needs no special path: reassigning the retained older configuration makes
/// it active, and this same function then stages its own tuple (which may be
/// older than the running version). A denied active release never falls
/// through to the unassigned retained previous release.
#[allow(clippy::too_many_arguments)]
pub fn stage_retained_release(
    state_path: &Path,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    current_version: &str,
    fetch: &dyn BundleFetch,
    staging_dir: &Path,
) -> Result<StageOutcome, ManagedUpdateError> {
    let state = super::load_state(state_path).map_err(|_| ManagedUpdateError::DownloadFailed)?;
    let active = match state.active.as_ref() {
        Some(active) => active,
        None => {
            return Ok(StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            });
        }
    };
    authorize_and_stage(
        state_path,
        active.envelope.configuration_id(),
        active.envelope.epoch(),
        now,
        client_version,
        bootstrap,
        verifier,
        current_version,
        fetch,
        staging_dir,
    )
}

/// Install the managed release after the daemon is fully shut down. The staged
/// bundle installs only while its binding still matches the retained active
/// authorization; a superseded, denied or missing authorization clears the
/// staging and installs nothing, so a deferred restart can never install a
/// release the fleet no longer authorizes. Only a staged, still-authorized
/// bundle installs here: there is no post-shutdown fetching, so explicit
/// cleanup that removed the staging stays authoritative.
#[allow(clippy::too_many_arguments)]
pub fn install_managed_update_post_shutdown(
    state_path: &Path,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    current_version: &str,
    installer: &dyn BundleInstall,
    staging_dir: &Path,
) -> Result<StagedInstallOutcome, ManagedUpdateError> {
    let state = super::load_state(state_path).map_err(|_| ManagedUpdateError::DownloadFailed)?;
    let Some(active) = state.active.as_ref() else {
        clear_staging_dir(staging_dir);
        return Ok(StagedInstallOutcome::NoStagedBundle);
    };
    let authorization = match authorize_desired_release(
        state_path,
        active.envelope.configuration_id(),
        active.envelope.epoch(),
        now,
        client_version,
        bootstrap,
        verifier,
    ) {
        Ok(authorization) => authorization,
        Err(_) => {
            clear_staging_dir(staging_dir);
            return Ok(StagedInstallOutcome::NoStagedBundle);
        }
    };
    if authorization.desired_release.version == current_version {
        clear_staging_dir(staging_dir);
        return Ok(StagedInstallOutcome::NoStagedBundle);
    }
    let staged_matches = match read_staged_binding(staging_dir) {
        Some(binding) => {
            binding_matches(&authorization, &binding)
                && staging_dir.join(MANIFEST_FILE).is_file()
                && staging_dir.join(SCRIPT_FILE).is_file()
        }
        None => false,
    };
    if !staged_matches {
        clear_staging_dir(staging_dir);
        return Ok(StagedInstallOutcome::NoStagedBundle);
    }
    let tag = authorization.desired_release.release_tag.clone();
    let outcome = install_staged_files(staging_dir, installer, &tag);
    // Terminal either way: a failed install must not restart-loop. Retry
    // re-stages from the retained authorization.
    clear_staging_dir(staging_dir);
    outcome
}

/// Install a staged bundle after the daemon is fully shut down. Re-verifies
/// the staged bytes against the pinned manifest before executing anything.
/// Missing staging is an idempotent no-op; staging is cleared on success and
/// on failure so a failed install can never restart-loop (retry re-stages).
pub fn install_staged_bundle(
    staging_dir: &Path,
    installer: &dyn BundleInstall,
) -> Result<StagedInstallOutcome, ManagedUpdateError> {
    let tag = match std::fs::read(staging_dir.join(TAG_FILE)) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| ManagedUpdateError::StageFailed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StagedInstallOutcome::NoStagedBundle);
        }
        Err(_) => return Err(ManagedUpdateError::StageFailed),
    };
    let outcome = install_staged_files(staging_dir, installer, &tag);
    // Terminal either way: a failed install must not restart-loop. Retry
    // re-stages from the retained authorization.
    clear_staging_dir(staging_dir);
    outcome
}

fn install_staged_files(
    staging_dir: &Path,
    installer: &dyn BundleInstall,
    tag: &str,
) -> Result<StagedInstallOutcome, ManagedUpdateError> {
    if !valid_staged_tag(tag) {
        return Err(ManagedUpdateError::UnexpectedTagOrUrl);
    }
    let version = read_staged_file(staging_dir, VERSION_FILE, 64)
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ManagedUpdateError::StageFailed))?;
    if version.is_empty() {
        return Err(ManagedUpdateError::StageFailed);
    }
    let pinned = read_staged_file(staging_dir, MANIFEST_SHA_FILE, 64)
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ManagedUpdateError::StageFailed))?;
    if pinned.len() != 64
        || !pinned
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManagedUpdateError::StageFailed);
    }
    let manifest = read_staged_file(staging_dir, MANIFEST_FILE, MAX_STAGED_MANIFEST_BYTES)?;
    crate::commands::upgrade::verify_sha256(&manifest, &pinned)
        .map_err(|_| ManagedUpdateError::ManifestDigestMismatch)?;
    let manifest_str =
        String::from_utf8(manifest).map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    let checksums = crate::commands::upgrade::parse_checksums(&manifest_str);
    let expected_asset = checksums
        .get(platform_script_name())
        .ok_or(ManagedUpdateError::MissingAssetChecksum)?;
    let script = read_staged_file(staging_dir, SCRIPT_FILE, MAX_STAGED_SCRIPT_BYTES)?;
    crate::commands::upgrade::verify_sha256(&script, expected_asset)
        .map_err(|_| ManagedUpdateError::AssetDigestMismatch)?;
    let script_str =
        std::str::from_utf8(&script).map_err(|_| ManagedUpdateError::ManifestNotUtf8)?;
    installer.run_installer(script_str, tag)?;
    Ok(StagedInstallOutcome::Installed {
        version,
        tag: tag.to_string(),
    })
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

    /// Fake fetcher for engineering-evidence unit tests only. Exposes no
    /// install or restart surface, so staging tests prove by construction that
    /// pre-shutdown code cannot execute anything.
    struct FakeFetch {
        manifest: Result<Vec<u8>, ManagedUpdateError>,
        asset: Result<Vec<u8>, ManagedUpdateError>,
        urls: RefCell<Vec<String>>,
    }

    impl FakeFetch {
        fn success(manifest: Vec<u8>, asset: Vec<u8>) -> Self {
            Self {
                manifest: Ok(manifest),
                asset: Ok(asset),
                urls: RefCell::new(Vec::new()),
            }
        }
    }

    impl BundleFetch for FakeFetch {
        fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ManagedUpdateError> {
            self.urls.borrow_mut().push(url.to_string());
            if url.ends_with("SHA256SUMS") {
                self.manifest.clone()
            } else {
                self.asset.clone()
            }
        }
    }

    /// Fake installer for post-shutdown unit tests only.
    struct FakeInstaller {
        fail: bool,
        install_tag: RefCell<Option<String>>,
        installs: RefCell<u32>,
    }

    impl FakeInstaller {
        fn success() -> Self {
            Self {
                fail: false,
                install_tag: RefCell::new(None),
                installs: RefCell::new(0),
            }
        }
    }

    impl BundleInstall for FakeInstaller {
        fn run_installer(&self, script: &str, tag: &str) -> Result<(), ManagedUpdateError> {
            assert!(!script.is_empty());
            *self.install_tag.borrow_mut() = Some(tag.to_string());
            *self.installs.borrow_mut() += 1;
            if self.fail {
                return Err(ManagedUpdateError::InstallFailed);
            }
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

    fn stage_outcome(
        path: &Path,
        id: &str,
        epoch: u64,
        staging: &Path,
        fetch: &dyn BundleFetch,
        verifier: &dyn ConfigurationVerifier,
    ) -> Result<StageOutcome, ManagedUpdateError> {
        authorize_and_stage(
            path,
            id,
            epoch,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            verifier,
            "1.6.19",
            fetch,
            staging,
        )
    }

    fn post_shutdown(
        path: &Path,
        staging: &Path,
        installer: &dyn BundleInstall,
        verifier: &dyn ConfigurationVerifier,
    ) -> Result<StagedInstallOutcome, ManagedUpdateError> {
        install_managed_update_post_shutdown(
            path,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            verifier,
            "1.6.19",
            installer,
            staging,
        )
    }

    #[test]
    fn no_authorization_means_zero_network_calls() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("staging");
        let fetch = FakeFetch::success(b"manifest".to_vec(), b"asset".to_vec());
        let outcome = stage_outcome(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            &staging,
            &fetch,
            &Verifier(VerificationResult::Verified),
        )
        .unwrap();
        assert_eq!(
            outcome,
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            }
        );
        assert!(fetch.urls.borrow().is_empty());
        assert!(!staging.exists());

        let retained = stage_retained_release(
            &path,
            "2026-10-10T01:00:00Z".parse().unwrap(),
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            "1.6.19",
            &fetch,
            &staging,
        )
        .unwrap();
        assert_eq!(
            retained,
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::NotRetained,
            }
        );
        assert!(fetch.urls.borrow().is_empty());
    }

    #[test]
    fn production_unavailable_verifier_means_zero_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("staging");
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

        let fetch = FakeFetch::success(manifest, b"script".to_vec());
        let outcome = stage_outcome(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            &staging,
            &fetch,
            &super::super::UnavailableVerifier,
        )
        .unwrap();
        assert_eq!(
            outcome,
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::VerificationUnavailable,
            }
        );
        assert!(fetch.urls.borrow().is_empty());
        assert!(!staging.exists());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn v1_and_legacy_state_cannot_stage_a_release() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");

        let v1_path = temp.path().join("fleet/v1.json");
        persist(
            &v1_path,
            &v1_config("dddddddd-dddd-4ddd-8ddd-dddddddddddd", 1),
        );
        let fetch = FakeFetch::success(b"m".to_vec(), b"a".to_vec());
        assert_eq!(
            stage_outcome(
                &v1_path,
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                1,
                &staging,
                &fetch,
                &Verifier(VerificationResult::Verified),
            )
            .unwrap(),
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::SchemaV1,
            }
        );
        assert!(fetch.urls.borrow().is_empty());

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
            stage_outcome(
                &legacy_path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                &staging,
                &fetch,
                &Verifier(VerificationResult::Verified),
            )
            .unwrap(),
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::MissingExactJson,
            }
        );
        assert!(fetch.urls.borrow().is_empty());
    }

    #[test]
    fn exact_authorized_release_verifies_pinned_manifest_and_exact_tag_assets() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let fetch = FakeFetch::success(manifest.clone(), asset.clone());
        let outcome = fetch_and_verify_bundle(&auth, "1.6.19", &fetch).unwrap();
        let FetchOutcome::Verified(bundle) = outcome else {
            panic!("expected verified bundle");
        };
        assert_eq!(bundle.version, "9.8.7");
        assert_eq!(bundle.tag, "v9.8.7");
        assert_eq!(bundle.manifest, manifest);
        assert_eq!(bundle.script, asset);
        assert_eq!(
            *fetch.urls.borrow(),
            vec![
                "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS"
                    .to_string(),
                format!(
                    "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/{}",
                    platform_script_name()
                ),
            ]
        );
        for url in fetch.urls.borrow().iter() {
            assert!(!url.contains("/worker/releases"));
            assert!(!url.contains("latest"));
        }
    }

    #[test]
    fn staged_bundle_installs_exact_tag_post_shutdown_and_clears_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("pending");
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
        let fetch = FakeFetch::success(manifest, asset);
        let verifier = Verifier(VerificationResult::Verified);
        assert_eq!(
            stage_outcome(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                &staging,
                &fetch,
                &verifier
            )
            .unwrap(),
            StageOutcome::Staged {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );

        let installer = FakeInstaller::success();
        let outcome = post_shutdown(&path, &staging, &installer, &verifier).unwrap();
        assert_eq!(
            outcome,
            StagedInstallOutcome::Installed {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );
        assert_eq!(*installer.install_tag.borrow(), Some("v9.8.7".to_string()));
        assert_eq!(*installer.installs.borrow(), 1);
        // Staging cleared: a second post-shutdown pass is an idempotent no-op
        // that performs no second install.
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
        );
        assert_eq!(*installer.installs.borrow(), 1);
    }

    #[test]
    fn superseded_denied_or_removed_authorization_never_installs_staged_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("pending");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let verifier = Verifier(VerificationResult::Verified);

        let asset_a = b"#!/bin/sh\necho a\n".to_vec();
        let manifest_a =
            format!("{}  {}\n", sha_hex(&asset_a), platform_script_name()).into_bytes();
        persist(
            &path,
            &v2_config(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                "9.8.7",
                "v9.8.7",
                &sha_hex(&manifest_a),
            ),
        );
        // Stage A, then the restart is deferred.
        let fetch = FakeFetch::success(manifest_a, asset_a);
        assert!(matches!(
            stage_outcome(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                &staging,
                &fetch,
                &verifier
            )
            .unwrap(),
            StageOutcome::Staged { .. }
        ));

        // Active becomes an unauthorized v1 configuration: the later
        // RestartAfterUpdate must not install A, and must clear the staging.
        let v1 = v1_config("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 2);
        assert_eq!(
            process_configuration(&v1, now, "1.6.19", &repositories(), &verifier, &path).result,
            super::super::AcknowledgementResult::Applied
        );
        let installer = FakeInstaller::success();
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
        );
        assert_eq!(*installer.installs.borrow(), 0);
        assert!(!staging.join(TAG_FILE).exists());

        // Active reassigned to B: the stale A bundle is cleared, never installed.
        let asset_b = b"#!/bin/sh\necho b\n".to_vec();
        let manifest_b =
            format!("{}  {}\n", sha_hex(&asset_b), platform_script_name()).into_bytes();
        persist(
            &path,
            &v2_config(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                3,
                "9.8.7",
                "v9.8.7",
                &sha_hex(&manifest_b),
            ),
        );
        let fetch = FakeFetch::success(manifest_b, asset_b);
        assert!(matches!(
            stage_outcome(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                3,
                &staging,
                &fetch,
                &verifier
            )
            .unwrap(),
            StageOutcome::Staged { .. }
        ));
        let asset_c = b"#!/bin/sh\necho c\n".to_vec();
        let manifest_c =
            format!("{}  {}\n", sha_hex(&asset_c), platform_script_name()).into_bytes();
        persist(
            &path,
            &v2_config(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                4,
                "9.8.8",
                "v9.8.8",
                &sha_hex(&manifest_c),
            ),
        );
        let installer = FakeInstaller::success();
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
        );
        assert_eq!(*installer.installs.borrow(), 0);
        assert!(!staging.join(TAG_FILE).exists());

        // Active removed entirely (offboarded): nothing installs.
        super::super::atomic_write_json(&path, &super::super::FleetState::default()).unwrap();
        let fetch = FakeFetch::success(b"m".to_vec(), b"a".to_vec());
        let installer = FakeInstaller::success();
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
        );
        assert_eq!(*installer.installs.borrow(), 0);
        assert!(fetch.urls.borrow().is_empty());
    }

    #[test]
    fn manifest_digest_mismatch_missing_asset_and_asset_mismatch_fail_closed() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();

        let auth = auth_for_test("9.8.7", "v9.8.7", &"b".repeat(64));
        let fetch = FakeFetch::success(b"tampered manifest".to_vec(), asset.clone());
        assert_eq!(
            fetch_and_verify_bundle(&auth, "1.6.19", &fetch),
            Err(ManagedUpdateError::ManifestDigestMismatch)
        );
        assert_eq!(fetch.urls.borrow().len(), 1);

        let manifest = format!("{}  other.bin\n", sha_hex(&asset)).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let fetch = FakeFetch::success(manifest, asset.clone());
        assert_eq!(
            fetch_and_verify_bundle(&auth, "1.6.19", &fetch),
            Err(ManagedUpdateError::MissingAssetChecksum)
        );
        assert_eq!(fetch.urls.borrow().len(), 1);

        let manifest = format!("{}  {}\n", "c".repeat(64), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let fetch = FakeFetch::success(manifest, asset.clone());
        assert_eq!(
            fetch_and_verify_bundle(&auth, "1.6.19", &fetch),
            Err(ManagedUpdateError::AssetDigestMismatch)
        );
        assert_eq!(fetch.urls.borrow().len(), 2);

        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let fetch = FakeFetch {
            manifest: Err(ManagedUpdateError::DownloadFailed),
            asset: Ok(asset),
            urls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            fetch_and_verify_bundle(&auth, "1.6.19", &fetch),
            Err(ManagedUpdateError::DownloadFailed)
        );
        assert_eq!(fetch.urls.borrow().len(), 1);
    }

    #[test]
    fn wrong_tag_or_url_fails_closed_before_any_fetch() {
        let manifest = b"anything\n".to_vec();
        let mut auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        auth.desired_release.manifest_url =
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.6/SHA256SUMS"
                .to_string();
        let fetch = FakeFetch::success(manifest, b"asset".to_vec());
        assert_eq!(
            fetch_and_verify_bundle(&auth, "1.6.19", &fetch),
            Err(ManagedUpdateError::UnexpectedTagOrUrl)
        );
        assert!(fetch.urls.borrow().is_empty());
    }

    #[test]
    fn retained_previous_uses_its_own_tuple_and_can_stage_older_version() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("staging");

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

        let fetch = FakeFetch::success(old_manifest, old_asset);
        let outcome = stage_outcome(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            &staging,
            &fetch,
            &Verifier(VerificationResult::Verified),
        )
        .unwrap();
        assert_eq!(
            outcome,
            StageOutcome::Staged {
                version: "9.8.6".to_string(),
                tag: "v9.8.6".to_string(),
            }
        );
        assert!(
            fetch
                .urls
                .borrow()
                .iter()
                .all(|url| url.contains("/v9.8.6/"))
        );
    }

    #[test]
    fn denied_active_release_never_falls_through_to_previous() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("staging");

        let previous = v2_config(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            "9.8.6",
            "v9.8.6",
            &"a".repeat(64),
        );
        persist(&path, &previous);
        // Active v1 can never authorize execution, even though a retained
        // previous v2 exists.
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let v1 = v1_config("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 2);
        assert_eq!(
            process_configuration(
                &v1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
                &path
            )
            .result,
            super::super::AcknowledgementResult::Applied
        );
        let fetch = FakeFetch::success(b"m".to_vec(), b"a".to_vec());
        let outcome = stage_retained_release(
            &path,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            "1.6.19",
            &fetch,
            &staging,
        )
        .unwrap();
        assert_eq!(
            outcome,
            StageOutcome::SkippedNotAuthorized {
                denial: ReleaseAuthorizationDenial::SchemaV1,
            }
        );
        assert!(fetch.urls.borrow().is_empty());
        assert!(!staging.exists());
    }

    #[test]
    fn equal_version_is_a_noop_with_zero_calls() {
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        let auth = auth_for_test("9.8.7", "v9.8.7", &sha_hex(&manifest));
        let fetch = FakeFetch::success(manifest, asset);
        assert_eq!(
            fetch_and_verify_bundle(&auth, "9.8.7", &fetch),
            Ok(FetchOutcome::NoopAlreadyAtVersion)
        );
        assert!(fetch.urls.borrow().is_empty());
    }

    #[test]
    fn failed_stage_preserves_state_and_stays_retryable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("staging");
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
        let verifier = Verifier(VerificationResult::Verified);

        // Stage through the real entry point, then fail the post-shutdown
        // install: staging clears instead of looping, state is preserved.
        let stager = FakeFetch::success(manifest.clone(), asset.clone());
        assert!(matches!(
            stage_outcome(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                &staging,
                &stager,
                &verifier
            )
            .unwrap(),
            StageOutcome::Staged { .. }
        ));
        let installer = FakeInstaller {
            fail: true,
            install_tag: RefCell::new(None),
            installs: RefCell::new(0),
        };
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier),
            Err(ManagedUpdateError::InstallFailed)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
        );
        assert_eq!(*installer.installs.borrow(), 1);

        // Retry re-stages from the retained authorization and installs.
        let retry = FakeFetch::success(manifest, asset);
        let outcome = stage_outcome(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            &staging,
            &retry,
            &verifier,
        )
        .unwrap();
        assert_eq!(
            outcome,
            StageOutcome::Staged {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );
        let installer = FakeInstaller::success();
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::Installed {
                version: "9.8.7".to_string(),
                tag: "v9.8.7".to_string(),
            }
        );
    }

    #[test]
    fn tampered_staging_fails_closed_and_clears() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let staging = temp.path().join("pending");
        let asset = b"#!/bin/sh\necho managed\n".to_vec();
        let manifest = format!("{}  {}\n", sha_hex(&asset), platform_script_name()).into_bytes();
        persist(
            &path,
            &v2_config(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                "9.8.7",
                "v9.8.7",
                &sha_hex(&manifest),
            ),
        );
        let verifier = Verifier(VerificationResult::Verified);
        let fetch = FakeFetch::success(manifest, asset);
        assert!(matches!(
            stage_outcome(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                &staging,
                &fetch,
                &verifier
            )
            .unwrap(),
            StageOutcome::Staged { .. }
        ));
        // Tamper with the staged manifest bytes: the binding still matches,
        // but the pinned digest no longer verifies them.
        std::fs::write(staging.join(MANIFEST_FILE), b"tampered").unwrap();
        let installer = FakeInstaller::success();
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier),
            Err(ManagedUpdateError::ManifestDigestMismatch)
        );
        assert_eq!(*installer.installs.borrow(), 0);
        assert_eq!(
            post_shutdown(&path, &staging, &installer, &verifier).unwrap(),
            StagedInstallOutcome::NoStagedBundle
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
            ManagedUpdateError::StageFailed,
            ManagedUpdateError::InstallFailed,
        ] {
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("trk_v1"));
            assert!(!rendered.contains("aaaaaaa"));
            assert!(!rendered.contains("github.com"));
        }
        let bundle = VerifiedBundle {
            version: "9.8.7".to_string(),
            tag: "v9.8.7".to_string(),
            manifest: b"manifest-bytes".to_vec(),
            script: b"script-bytes".to_vec(),
        };
        let rendered = format!("{bundle:?}");
        assert!(!rendered.contains("manifest-bytes"));
        assert!(!rendered.contains("script-bytes"));
    }
}
