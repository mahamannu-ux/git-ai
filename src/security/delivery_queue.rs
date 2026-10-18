//! Durable security-v2 queue and Numbat tail checkpoint.
//!
//! Rows contain only lease-minimized projections. Raw Numbat source records
//! never enter SQLite. The checkpoint and inserted rows commit atomically.

use crate::error::GitAiError;
use crate::metrics::delivery::MetricDeliveryHealthBinding;
use crate::security::records::ProjectedRecord;
use crate::security::tail::{FileIdentity, TailCheckpoint, TailRead};
use chrono::NaiveDate;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_ATTEMPTS: u32 = 6;
const PROCESSING_LOCK_TIMEOUT_SECS: u64 = 10 * 60;
pub(crate) const FIRST_RETRY_DELAY_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSecurityRecord {
    pub id: i64,
    pub kind: String,
    pub record_id: String,
    pub projection_json: String,
    pub lease_id: String,
    pub attempts: u32,
    pub delivery_binding: MetricDeliveryHealthBinding,
}

pub struct SecurityRecordQueue {
    connection: Connection,
    legacy_rows_dropped: usize,
}

impl SecurityRecordQueue {
    pub fn open_at_path(path: &Path) -> Result<Self, GitAiError> {
        let connection = crate::sqlite::open_with_memory_limits(path)?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS security_record_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                record_id TEXT NOT NULL UNIQUE,
                projection_json TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                queued_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at INTEGER NOT NULL,
                processing_started_at INTEGER,
                last_error_code TEXT,
                delivery_tenant_id TEXT NOT NULL,
                delivery_api_base_url TEXT NOT NULL,
                delivery_credential_key_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS security_record_queue_pending
                ON security_record_queue (next_retry_at, id)
                WHERE processing_started_at IS NULL AND attempts < 6;
            CREATE TABLE IF NOT EXISTS security_tail_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                device TEXT, inode TEXT, byte_offset INTEGER NOT NULL,
                partial_len INTEGER NOT NULL, last_rotation_local_date TEXT
            );
            CREATE TABLE IF NOT EXISTS security_shipper_counters (
                name TEXT PRIMARY KEY, value INTEGER NOT NULL
            );
            "#,
        )?;
        let legacy_exists = connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='security_finding_queue'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let legacy_rows_dropped = if legacy_exists {
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM security_finding_queue", [], |row| {
                    row.get(0)
                })?;
            connection.execute("DELETE FROM security_finding_queue", [])?;
            connection.execute(
                "INSERT INTO security_shipper_counters(name,value) VALUES ('legacy_task6_rows_dropped',?1)
                 ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                params![count],
            )?;
            usize::try_from(count.max(0)).unwrap_or(usize::MAX)
        } else {
            0
        };
        Ok(Self {
            connection,
            legacy_rows_dropped,
        })
    }

    pub fn legacy_rows_dropped(&self) -> usize {
        self.legacy_rows_dropped
    }

    pub fn checkpoint(&self) -> Result<TailCheckpoint, GitAiError> {
        self.connection
            .query_row(
                "SELECT device,inode,byte_offset,partial_len,last_rotation_local_date
                   FROM security_tail_state WHERE singleton=1",
                [],
                |row| {
                    let device = row.get::<_, Option<String>>(0)?;
                    let inode = row.get::<_, Option<String>>(1)?;
                    let date = row.get::<_, Option<String>>(4)?;
                    Ok(TailCheckpoint {
                        identity: device.zip(inode).and_then(|(device, inode)| {
                            Some(FileIdentity {
                                device: device.parse().ok()?,
                                inode: inode.parse().ok()?,
                            })
                        }),
                        offset: row.get::<_, i64>(2)?.max(0) as u64,
                        partial_len: row.get::<_, i64>(3)?.max(0) as u64,
                        last_rotation_local_date: date
                            .and_then(|date| NaiveDate::parse_from_str(&date, "%Y-%m-%d").ok()),
                    })
                },
            )
            .optional()
            .map(|value| value.unwrap_or_default())
            .map_err(GitAiError::from)
    }

    pub fn commit_poll(
        &mut self,
        read: &TailRead,
        rotation_local_date: NaiveDate,
        records: &[(&ProjectedRecord, &MetricDeliveryHealthBinding)],
        counters: &BTreeMap<String, u64>,
        queued_at: u64,
    ) -> Result<(), GitAiError> {
        let queued_at = sql_i64(queued_at, "timestamp")?;
        let tx = self.connection.transaction()?;
        for (record, binding) in records {
            validate_binding(binding)?;
            let projection_json = serde_json::to_string(&record.json)?;
            let inserted = tx.execute(
                "INSERT INTO security_record_queue(
                    kind,record_id,projection_json,lease_id,queued_at,next_retry_at,
                    delivery_tenant_id,delivery_api_base_url,delivery_credential_key_id)
                 VALUES(?1,?2,?3,?4,?5,?5,?6,?7,?8)
                 ON CONFLICT(record_id) DO NOTHING",
                params![
                    record.kind,
                    record.record_id,
                    projection_json,
                    record.lease_id,
                    queued_at,
                    binding.tenant_id,
                    binding.api_base_url,
                    binding.credential_key_id,
                ],
            )?;
            if inserted == 0 {
                let existing = tx.query_row(
                    "SELECT kind,projection_json,lease_id,delivery_tenant_id,
                            delivery_api_base_url,delivery_credential_key_id
                       FROM security_record_queue WHERE record_id=?1",
                    params![record.record_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    },
                )?;
                if existing
                    != (
                        record.kind.clone(),
                        projection_json,
                        record.lease_id.clone(),
                        binding.tenant_id.clone(),
                        binding.api_base_url.clone(),
                        binding.credential_key_id.clone(),
                    )
                {
                    return Err(GitAiError::Generic(
                        "security record ID collision".to_string(),
                    ));
                }
            }
        }
        tx.execute(
            "INSERT INTO security_tail_state(singleton,device,inode,byte_offset,partial_len,last_rotation_local_date)
             VALUES(1,?1,?2,?3,?4,?5)
             ON CONFLICT(singleton) DO UPDATE SET device=excluded.device,inode=excluded.inode,
                byte_offset=excluded.byte_offset,partial_len=excluded.partial_len,
                last_rotation_local_date=excluded.last_rotation_local_date",
            params![
                read.identity.device.to_string(),
                read.identity.inode.to_string(),
                sql_i64(read.next_offset, "offset")?,
                sql_i64(read.partial_len, "partial length")?,
                rotation_local_date.format("%Y-%m-%d").to_string(),
            ],
        )?;
        for (name, value) in counters {
            tx.execute(
                "INSERT INTO security_shipper_counters(name,value) VALUES(?1,?2)
                 ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                params![name, sql_i64(*value, "counter")?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn dequeue_pending(
        &mut self,
        limit: usize,
        now: u64,
    ) -> Result<Vec<QueuedSecurityRecord>, GitAiError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = sql_i64(now, "timestamp")?;
        let stale = now.saturating_sub(PROCESSING_LOCK_TIMEOUT_SECS as i64);
        let tx = self.connection.transaction()?;
        tx.execute(
            "UPDATE security_record_queue SET processing_started_at=NULL
              WHERE processing_started_at IS NOT NULL AND processing_started_at<=?1",
            params![stale],
        )?;
        let ids = {
            let mut statement = tx.prepare(
                "SELECT id FROM security_record_queue
                  WHERE processing_started_at IS NULL AND next_retry_at<=?1 AND attempts<?2
                  ORDER BY next_retry_at,id LIMIT ?3",
            )?;
            statement
                .query_map(params![now, i64::from(MAX_ATTEMPTS), limit as i64], |row| {
                    row.get(0)
                })?
                .collect::<Result<Vec<i64>, _>>()?
        };
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            tx.execute(
                "UPDATE security_record_queue SET processing_started_at=?1 WHERE id=?2",
                params![now, id],
            )?;
            records.push(tx.query_row(
                "SELECT id,kind,record_id,projection_json,lease_id,attempts,
                        delivery_tenant_id,delivery_api_base_url,delivery_credential_key_id
                   FROM security_record_queue WHERE id=?1",
                params![id],
                |row| {
                    Ok(QueuedSecurityRecord {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        record_id: row.get(2)?,
                        projection_json: row.get(3)?,
                        lease_id: row.get(4)?,
                        attempts: row.get::<_, i64>(5)?.max(0) as u32,
                        delivery_binding: MetricDeliveryHealthBinding {
                            tenant_id: row.get(6)?,
                            api_base_url: row.get(7)?,
                            credential_key_id: row.get(8)?,
                        },
                    })
                },
            )?);
        }
        tx.commit()?;
        Ok(records)
    }

    pub fn delete(&mut self, ids: &[i64]) -> Result<(), GitAiError> {
        let tx = self.connection.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM security_record_queue WHERE id=?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_counted(&mut self, ids: &[i64], code: &str) -> Result<(), GitAiError> {
        let tx = self.connection.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM security_record_queue WHERE id=?1", params![id])?;
        }
        tx.execute(
            "INSERT INTO security_shipper_counters(name,value) VALUES(?1,?2)
             ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
            params![
                format!("terminal:{code}"),
                sql_i64(ids.len() as u64, "counter")?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_retry(
        &mut self,
        ids: &[i64],
        code: &str,
        failed_at: u64,
        retry_after: Option<u64>,
    ) -> Result<(), GitAiError> {
        let failed_at = sql_i64(failed_at, "timestamp")?;
        let tx = self.connection.transaction()?;
        for id in ids {
            let attempts: i64 = tx.query_row(
                "SELECT attempts FROM security_record_queue WHERE id=?1",
                params![id],
                |row| row.get(0),
            )?;
            let delay = retry_after.unwrap_or_else(|| {
                FIRST_RETRY_DELAY_SECS.saturating_mul(1_u64 << attempts.clamp(0, 5) as u32)
            });
            tx.execute(
                "UPDATE security_record_queue SET attempts=attempts+1,next_retry_at=?1,
                    processing_started_at=NULL,last_error_code=?2 WHERE id=?3",
                params![failed_at.saturating_add(delay as i64), code, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn replace_projection(
        &mut self,
        id: i64,
        projection: &serde_json::Value,
    ) -> Result<(), GitAiError> {
        self.connection.execute(
            "UPDATE security_record_queue SET projection_json=?1,processing_started_at=NULL,next_retry_at=0 WHERE id=?2",
            params![serde_json::to_string(projection)?,id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn count(&self) -> usize {
        self.connection
            .query_row("SELECT COUNT(*) FROM security_record_queue", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap() as usize
    }

    #[cfg(test)]
    pub(crate) fn counter(&self, name: &str) -> u64 {
        self.connection
            .query_row(
                "SELECT value FROM security_shipper_counters WHERE name=?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap()
            .unwrap_or_default()
            .max(0) as u64
    }
}

fn validate_binding(binding: &MetricDeliveryHealthBinding) -> Result<(), GitAiError> {
    if binding.tenant_id.trim().is_empty()
        || binding.api_base_url.trim().is_empty()
        || binding.credential_key_id.trim().is_empty()
    {
        return Err(GitAiError::Generic(
            "security record delivery binding is invalid".to_string(),
        ));
    }
    Ok(())
}

fn sql_i64(value: u64, field: &str) -> Result<i64, GitAiError> {
    i64::try_from(value).map_err(|_| GitAiError::Generic(format!("security {field} is invalid")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::tail::{TailEntry, TailEntryKind};
    use serde_json::json;

    fn binding() -> MetricDeliveryHealthBinding {
        MetricDeliveryHealthBinding {
            tenant_id: "tenant".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "ABCDEFGHIJKLMNOP".into(),
        }
    }
    fn read(offset: u64) -> TailRead {
        TailRead {
            identity: FileIdentity {
                device: 7,
                inode: 9,
            },
            reset: false,
            start_offset: 0,
            next_offset: offset,
            partial_len: 3,
            file_len: offset + 3,
            reached_eof: true,
            entries: vec![TailEntry {
                end_offset: offset,
                kind: TailEntryKind::Record(vec![]),
            }],
        }
    }
    fn record() -> ProjectedRecord {
        ProjectedRecord {
            kind: "finding".into(),
            record_id: format!("sha256:{}", "a".repeat(64)),
            lease_id: "lease".into(),
            json: json!({"kind":"finding","record_id":format!("sha256:{}", "a".repeat(64))}),
        }
    }

    #[test]
    fn queue_commit_atomically_persists_minimized_projection_and_checkpoint() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let record = record();
        let binding = binding();
        queue
            .commit_poll(
                &read(42),
                NaiveDate::from_ymd_opt(2026, 10, 17).unwrap(),
                &[(&record, &binding)],
                &BTreeMap::new(),
                100,
            )
            .unwrap();
        assert_eq!(queue.count(), 1);
        assert_eq!(queue.checkpoint().unwrap().offset, 42);
        let queued = queue.dequeue_pending(500, 100).unwrap();
        assert_eq!(queued[0].projection_json, record.json.to_string());
        assert!(!queued[0].projection_json.contains("tool_input"));
        assert_eq!(queued[0].delivery_binding, binding);
    }

    #[test]
    fn no_lease_drop_advances_checkpoint_without_queueing() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        queue
            .commit_poll(
                &read(84),
                NaiveDate::from_ymd_opt(2026, 10, 17).unwrap(),
                &[],
                &BTreeMap::from([("lease_absent".into(), 1)]),
                100,
            )
            .unwrap();
        assert_eq!(queue.count(), 0);
        assert_eq!(queue.checkpoint().unwrap().offset, 84);
    }

    #[test]
    fn legacy_task6_rows_are_dropped_once_and_counted() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("queue.db");
        let connection = crate::sqlite::open_with_memory_limits(&path).unwrap();
        connection.execute_batch("CREATE TABLE security_finding_queue(id INTEGER PRIMARY KEY); INSERT INTO security_finding_queue VALUES(1);").unwrap();
        drop(connection);
        let first = SecurityRecordQueue::open_at_path(&path).unwrap();
        assert_eq!(first.legacy_rows_dropped(), 1);
        drop(first);
        assert_eq!(
            SecurityRecordQueue::open_at_path(&path)
                .unwrap()
                .legacy_rows_dropped(),
            0
        );
    }

    #[test]
    fn filesystem_identity_round_trips_full_unsigned_values() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let mut tail = read(7);
        tail.identity = FileIdentity {
            device: u64::MAX,
            inode: u64::MAX - 1,
        };
        queue
            .commit_poll(
                &tail,
                NaiveDate::from_ymd_opt(2026, 10, 18).unwrap(),
                &[],
                &BTreeMap::new(),
                100,
            )
            .unwrap();
        assert_eq!(queue.checkpoint().unwrap().identity, Some(tail.identity));
    }

    #[test]
    fn terminal_drop_is_deleted_and_counted_by_safe_code() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let record = record();
        let binding = binding();
        queue
            .commit_poll(
                &read(1),
                NaiveDate::from_ymd_opt(2026, 10, 18).unwrap(),
                &[(&record, &binding)],
                &BTreeMap::new(),
                100,
            )
            .unwrap();
        let id = queue.dequeue_pending(1, 100).unwrap()[0].id;
        queue
            .delete_counted(&[id], "SECURITY_V2_UNKNOWN_FIELD")
            .unwrap();
        assert_eq!(queue.count(), 0);
        assert_eq!(queue.counter("terminal:SECURITY_V2_UNKNOWN_FIELD"), 1);
    }
}
