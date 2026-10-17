//! Numbat NDJSON tailing and local rotation.
//!
//! Behaviour rewritten from `perplexityai/numbat@20a5a52` `ship`; no source
//! code is copied. The durable caller advances its checkpoint only after the
//! returned complete entries have been queued or deliberately dropped.

use crate::error::GitAiError;
use chrono::NaiveDate;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES_PER_POLL: usize = 500;
pub const ROTATE_AFTER_BYTES: u64 = 64 * 1024 * 1024;
pub const RETAIN_ROTATIONS_DAYS: i64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TailCheckpoint {
    pub identity: Option<FileIdentity>,
    pub offset: u64,
    pub partial_len: u64,
    pub last_rotation_local_date: Option<NaiveDate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailEntryKind {
    Record(Vec<u8>),
    Oversized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailEntry {
    pub end_offset: u64,
    pub kind: TailEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailRead {
    pub identity: FileIdentity,
    pub reset: bool,
    pub start_offset: u64,
    pub next_offset: u64,
    pub partial_len: u64,
    pub file_len: u64,
    pub reached_eof: bool,
    pub entries: Vec<TailEntry>,
}

pub fn read_available(
    path: &Path,
    checkpoint: &TailCheckpoint,
    max_entries: usize,
) -> Result<TailRead, GitAiError> {
    let mut file = open_checkpoint_source(path, checkpoint)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(GitAiError::Generic(
            "Numbat record input is not a regular file".to_string(),
        ));
    }
    let identity = file_identity(&metadata);
    let file_len = metadata.len();
    let reset = checkpoint.identity.is_some_and(|saved| saved != identity)
        || checkpoint.offset > file_len
        || (checkpoint.identity.is_none() && checkpoint.offset != 0);
    let start_offset = if reset { 0 } else { checkpoint.offset };
    file.seek(SeekFrom::Start(start_offset))?;

    let mut entries = Vec::new();
    let mut line = Vec::new();
    let mut oversized = false;
    let mut position = start_offset;
    let mut next_offset = start_offset;
    let mut reached_eof = false;
    let mut buffer = [0_u8; 64 * 1024];

    if max_entries > 0 {
        'read: loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                reached_eof = true;
                break;
            }
            for byte in &buffer[..count] {
                position = position.saturating_add(1);
                if *byte == b'\n' {
                    let kind = if oversized || line.len() > MAX_RECORD_BYTES {
                        TailEntryKind::Oversized
                    } else {
                        TailEntryKind::Record(std::mem::take(&mut line))
                    };
                    entries.push(TailEntry {
                        end_offset: position,
                        kind,
                    });
                    line.clear();
                    oversized = false;
                    next_offset = position;
                    if entries.len() == max_entries {
                        break 'read;
                    }
                } else if !oversized {
                    if line.len() == MAX_RECORD_BYTES {
                        line.clear();
                        oversized = true;
                    } else {
                        line.push(*byte);
                    }
                }
            }
        }
    }

    let partial_len = if reached_eof {
        position.saturating_sub(next_offset)
    } else {
        0
    };
    Ok(TailRead {
        identity,
        reset,
        start_offset,
        next_offset,
        partial_len,
        file_len,
        reached_eof,
        entries,
    })
}

pub fn rotate_if_due(
    path: &Path,
    checkpoint: &TailCheckpoint,
    local_date: NaiveDate,
    utc_date: NaiveDate,
) -> Result<Option<PathBuf>, GitAiError> {
    let file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    let identity = file_identity(&metadata);
    if checkpoint.identity != Some(identity)
        || checkpoint.offset != metadata.len()
        || checkpoint.partial_len != 0
    {
        return Ok(None);
    }
    let crossed_midnight = checkpoint
        .last_rotation_local_date
        .is_some_and(|previous| previous < local_date);
    if metadata.len() <= ROTATE_AFTER_BYTES && !crossed_midnight {
        return Ok(None);
    }
    // Close the descriptor before rename so Windows follows the same behavior.
    drop(file);

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GitAiError::Generic("Numbat record path is invalid".to_string()))?;
    for suffix in 1_u32..=u32::MAX {
        let candidate = path.with_file_name(format!("{file_name}.{utc_date}.{suffix}"));
        if !candidate.try_exists()? {
            std::fs::rename(path, &candidate)?;
            return Ok(Some(candidate));
        }
    }
    Err(GitAiError::Generic(
        "Numbat record rotation suffixes are exhausted".to_string(),
    ))
}

pub fn delete_expired_rotations(path: &Path, utc_date: NaiveDate) -> Result<usize, GitAiError> {
    delete_expired_rotations_except(path, utc_date, None)
}

pub fn delete_expired_rotations_except(
    path: &Path,
    utc_date: NaiveDate,
    preserve: Option<FileIdentity>,
) -> Result<usize, GitAiError> {
    let parent = path.parent().ok_or_else(|| {
        GitAiError::Generic("Numbat record path has no parent directory".to_string())
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GitAiError::Generic("Numbat record path is invalid".to_string()))?;
    let prefix = format!("{file_name}.");
    let mut deleted = 0;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some((date, suffix)) = rest.rsplit_once('.') else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(date) = NaiveDate::parse_from_str(date, "%Y-%m-%d") else {
            continue;
        };
        if utc_date.signed_duration_since(date).num_days() > RETAIN_ROTATIONS_DAYS {
            if preserve.is_some_and(|identity| {
                open_no_follow(&entry.path())
                    .and_then(|file| Ok(file_identity(&file.metadata()?)))
                    .is_ok_and(|candidate| candidate == identity)
            }) {
                continue;
            }
            std::fs::remove_file(entry.path())?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

fn open_checkpoint_source(path: &Path, checkpoint: &TailCheckpoint) -> Result<File, GitAiError> {
    let active = open_no_follow(path).ok();
    if let (Some(file), Some(saved)) = (active.as_ref(), checkpoint.identity)
        && file_identity(&file.metadata()?) == saved
    {
        return open_no_follow(path);
    }

    if let Some(saved) = checkpoint.identity
        && let Some(rotated) = find_rotation(path, saved)?
    {
        let metadata = rotated.metadata()?;
        // A just-rotated inode remains the checkpoint source until any append
        // that raced the rename has been consumed. Once it is stable at the
        // saved EOF, move to a newly-created active file.
        if checkpoint.offset < metadata.len() || checkpoint.partial_len != 0 || active.is_none() {
            return Ok(rotated);
        }
    }

    active.ok_or_else(|| GitAiError::Generic("Numbat record input is unavailable".to_string()))
}

fn find_rotation(path: &Path, identity: FileIdentity) -> Result<Option<File>, GitAiError> {
    let parent = path.parent().ok_or_else(|| {
        GitAiError::Generic("Numbat record path has no parent directory".to_string())
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GitAiError::Generic("Numbat record path is invalid".to_string()))?;
    let prefix = format!("{file_name}.");
    if !parent.try_exists()? {
        return Ok(None);
    }
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&prefix) || entry.file_type()?.is_symlink() {
            continue;
        }
        let Ok(file) = open_no_follow(&entry.path()) else {
            continue;
        };
        let metadata = file.metadata()?;
        if metadata.is_file() && file_identity(&metadata) == identity {
            return Ok(Some(file));
        }
    }
    Ok(None)
}

fn open_no_follow(path: &Path) -> Result<File, GitAiError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        return OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(GitAiError::from);
    }
    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(GitAiError::Generic(
                "Numbat record input must not be a symlink".to_string(),
            ));
        }
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(GitAiError::from)
    }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;
    FileIdentity {
        device: u64::from(metadata.volume_serial_number().unwrap_or_default()),
        inode: metadata.file_index().unwrap_or_default(),
    }
}

#[cfg(not(any(unix, windows)))]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: metadata.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn partial_line_waits_for_newline_and_restart_uses_committed_offset() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        write(&path, b"one\ntwo");

        let first = read_available(&path, &TailCheckpoint::default(), 500).unwrap();
        assert_eq!(first.entries.len(), 1);
        assert_eq!(
            first.entries[0].kind,
            TailEntryKind::Record(b"one".to_vec())
        );
        assert_eq!(first.next_offset, 4);
        assert_eq!(first.partial_len, 3);

        let saved = TailCheckpoint {
            identity: Some(first.identity),
            offset: first.next_offset,
            partial_len: first.partial_len,
            last_rotation_local_date: None,
        };
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        let second = read_available(&path, &saved, 500).unwrap();
        assert_eq!(second.entries.len(), 1);
        assert_eq!(
            second.entries[0].kind,
            TailEntryKind::Record(b"two".to_vec())
        );
        assert_eq!(second.next_offset, 8);
        assert_eq!(second.partial_len, 0);
    }

    #[test]
    fn truncation_and_replacement_reset_to_zero() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        write(&path, b"old\n");
        let first = read_available(&path, &TailCheckpoint::default(), 500).unwrap();
        let saved = TailCheckpoint {
            identity: Some(first.identity),
            offset: first.next_offset,
            partial_len: 0,
            last_rotation_local_date: None,
        };

        write(&path, b"n\n");
        let truncated = read_available(&path, &saved, 500).unwrap();
        assert!(truncated.reset);
        assert_eq!(truncated.start_offset, 0);
        assert_eq!(
            truncated.entries[0].kind,
            TailEntryKind::Record(b"n".to_vec())
        );

        std::fs::remove_file(&path).unwrap();
        write(&path, b"replacement\n");
        let replaced = read_available(&path, &saved, 500).unwrap();
        assert!(replaced.reset);
        assert_ne!(replaced.identity, first.identity);
        assert_eq!(replaced.start_offset, 0);
    }

    #[test]
    fn oversized_line_is_counted_without_retaining_its_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        let mut file = File::create(&path).unwrap();
        file.write_all(&vec![b'x'; MAX_RECORD_BYTES + 1]).unwrap();
        file.write_all(b"\nok\n").unwrap();

        let read = read_available(&path, &TailCheckpoint::default(), 500).unwrap();
        assert_eq!(read.entries.len(), 2);
        assert_eq!(read.entries[0].kind, TailEntryKind::Oversized);
        assert_eq!(read.entries[1].kind, TailEntryKind::Record(b"ok".to_vec()));
        assert_eq!(read.next_offset, read.file_len);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_input_is_refused() {
        let temp = tempfile::TempDir::new().unwrap();
        let target = temp.path().join("target.ndjson");
        let link = temp.path().join("records.ndjson");
        write(&target, b"one\n");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_available(&link, &TailCheckpoint::default(), 500).is_err());
    }

    #[test]
    fn rotation_requires_a_fully_checkpointed_file_and_uses_next_suffix() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        write(&path, b"one\n");
        let read = read_available(&path, &TailCheckpoint::default(), 500).unwrap();
        let local_date = NaiveDate::from_ymd_opt(2026, 10, 18).unwrap();
        let utc_date = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let incomplete = TailCheckpoint {
            identity: Some(read.identity),
            offset: 0,
            partial_len: 0,
            last_rotation_local_date: Some(NaiveDate::from_ymd_opt(2026, 10, 17).unwrap()),
        };
        assert_eq!(
            rotate_if_due(&path, &incomplete, local_date, utc_date).unwrap(),
            None
        );

        let prior = path.with_file_name("records.ndjson.2026-10-17.1");
        write(&prior, b"prior\n");
        let complete = TailCheckpoint {
            identity: Some(read.identity),
            offset: read.file_len,
            partial_len: 0,
            last_rotation_local_date: Some(NaiveDate::from_ymd_opt(2026, 10, 17).unwrap()),
        };
        let rotated = rotate_if_due(&path, &complete, local_date, utc_date)
            .unwrap()
            .unwrap();
        assert_eq!(rotated.file_name().unwrap(), "records.ndjson.2026-10-17.2");
        assert!(!path.exists());
        assert_eq!(std::fs::read(rotated).unwrap(), b"one\n");
    }

    #[test]
    fn retention_deletes_only_rotations_older_than_seven_days() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        for name in [
            "records.ndjson.2026-10-09.1",
            "records.ndjson.2026-10-10.1",
            "records.ndjson.2026-10-17.1",
            "records.ndjson.unrelated",
        ] {
            write(&temp.path().join(name), b"x");
        }
        let today = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        assert_eq!(delete_expired_rotations(&path, today).unwrap(), 1);
        assert!(!temp.path().join("records.ndjson.2026-10-09.1").exists());
        assert!(temp.path().join("records.ndjson.2026-10-10.1").exists());
        assert!(temp.path().join("records.ndjson.unrelated").exists());
    }

    #[test]
    fn checkpointed_rotated_inode_is_drained_before_new_active_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        write(&path, b"one\n");
        let first = read_available(&path, &TailCheckpoint::default(), 500).unwrap();
        let saved = TailCheckpoint {
            identity: Some(first.identity),
            offset: first.next_offset,
            partial_len: 0,
            last_rotation_local_date: None,
        };
        let rotated = temp.path().join("records.ndjson.2026-10-17.1");
        std::fs::rename(&path, &rotated).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&rotated)
            .unwrap()
            .write_all(b"late\n")
            .unwrap();
        write(&path, b"new\n");

        let late = read_available(&path, &saved, 500).unwrap();
        assert_eq!(late.identity, first.identity);
        assert_eq!(
            late.entries[0].kind,
            TailEntryKind::Record(b"late".to_vec())
        );
        let drained = TailCheckpoint {
            identity: Some(late.identity),
            offset: late.next_offset,
            partial_len: late.partial_len,
            last_rotation_local_date: None,
        };
        let active = read_available(&path, &drained, 500).unwrap();
        assert!(active.reset);
        assert_eq!(
            active.entries[0].kind,
            TailEntryKind::Record(b"new".to_vec())
        );
    }

    #[test]
    fn retention_preserves_the_checkpointed_rotation() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("records.ndjson");
        let rotated = temp.path().join("records.ndjson.2026-10-01.1");
        write(&rotated, b"held\n");
        let identity = file_identity(&std::fs::metadata(&rotated).unwrap());
        let today = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        assert_eq!(
            delete_expired_rotations_except(&path, today, Some(identity)).unwrap(),
            0
        );
        assert!(rotated.exists());
    }
}
