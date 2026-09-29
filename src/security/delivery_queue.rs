//! Durable, metadata-only queue for Task6 security findings.
//!
//! This queue is intentionally disconnected from live hooks and networking.
//! It persists only the closed upload projection and the non-secret Task4
//! delivery binding captured at enqueue time.

use crate::error::GitAiError;
use crate::metrics::delivery::EvidenceDeliveryBinding;
use crate::security::SecurityFindingUploadBatch;
use rusqlite::{Connection, params};
use std::path::Path;

const MAX_ATTEMPTS: u32 = 6;
const PROCESSING_LOCK_TIMEOUT_SECS: u64 = 10 * 60;
const FIRST_RETRY_DELAY_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFindingFailureClass {
    TemporaryTransport,
    ServerUnavailable,
    RateLimited,
}

impl SecurityFindingFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::TemporaryTransport => "temporary_transport_error",
            Self::ServerUnavailable => "server_unavailable",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSecurityFinding {
    pub id: i64,
    pub finding_json: String,
    pub attempts: u32,
    pub delivery_binding: EvidenceDeliveryBinding,
}

pub struct SecurityFindingQueue {
    connection: Connection,
}

impl SecurityFindingQueue {
    pub fn open_at_path(path: &Path) -> Result<Self, GitAiError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS security_finding_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_json TEXT NOT NULL,
                queued_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at INTEGER NOT NULL,
                processing_started_at INTEGER,
                delivered_at INTEGER,
                last_error_class TEXT,
                delivery_tenant_id TEXT NOT NULL,
                delivery_repository_id TEXT NOT NULL,
                delivery_repository_url TEXT NOT NULL,
                delivery_api_base_url TEXT NOT NULL,
                delivery_credential_key_id TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS security_finding_queue_pending
                ON security_finding_queue (next_retry_at, id)
                WHERE delivered_at IS NULL AND processing_started_at IS NULL;
            "#,
        )?;
        Ok(Self { connection })
    }

    pub fn enqueue(
        &mut self,
        batch: &SecurityFindingUploadBatch,
        binding: &EvidenceDeliveryBinding,
        queued_at: u64,
    ) -> Result<i64, GitAiError> {
        validate_binding(binding)?;
        if batch.repository_id() != binding.repository_id {
            return Err(GitAiError::Generic(
                "security finding repository does not match its delivery binding".to_string(),
            ));
        }
        let finding_json = serde_json::to_string(batch)?;
        self.connection.execute(
            "INSERT INTO security_finding_queue (
                finding_json, queued_at, next_retry_at,
                delivery_tenant_id, delivery_repository_id, delivery_repository_url,
                delivery_api_base_url, delivery_credential_key_id
             ) VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                finding_json,
                as_sql_timestamp(queued_at)?,
                binding.tenant_id,
                binding.repository_id,
                binding.repository_url,
                binding.api_base_url,
                binding.credential_key_id,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn dequeue_pending(
        &mut self,
        limit: usize,
        now: u64,
    ) -> Result<Vec<QueuedSecurityFinding>, GitAiError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = as_sql_timestamp(now)?;
        let stale_before = now.saturating_sub(PROCESSING_LOCK_TIMEOUT_SECS as i64);
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE security_finding_queue
                SET processing_started_at = NULL
              WHERE delivered_at IS NULL
                AND processing_started_at IS NOT NULL
                AND processing_started_at <= ?1",
            params![stale_before],
        )?;

        let ids = {
            let mut statement = transaction.prepare(
                "SELECT id FROM security_finding_queue
                  WHERE delivered_at IS NULL
                    AND processing_started_at IS NULL
                    AND next_retry_at <= ?1
                    AND attempts < ?2
                  ORDER BY next_retry_at ASC, id ASC
                  LIMIT ?3",
            )?;
            statement
                .query_map(params![now, i64::from(MAX_ATTEMPTS), limit as i64], |row| {
                    row.get::<_, i64>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };

        for id in &ids {
            transaction.execute(
                "UPDATE security_finding_queue
                    SET processing_started_at = ?1
                  WHERE id = ?2 AND processing_started_at IS NULL",
                params![now, id],
            )?;
        }

        let mut records = Vec::with_capacity(ids.len());
        {
            let mut statement = transaction.prepare(
                "SELECT id, finding_json, attempts,
                        delivery_tenant_id, delivery_repository_id, delivery_repository_url,
                        delivery_api_base_url, delivery_credential_key_id
                   FROM security_finding_queue WHERE id = ?1",
            )?;
            for id in ids {
                records.push(statement.query_row(params![id], |row| {
                    Ok(QueuedSecurityFinding {
                        id: row.get(0)?,
                        finding_json: row.get(1)?,
                        attempts: row.get::<_, i64>(2)?.max(0) as u32,
                        delivery_binding: EvidenceDeliveryBinding {
                            tenant_id: row.get(3)?,
                            repository_id: row.get(4)?,
                            repository_url: row.get(5)?,
                            api_base_url: row.get(6)?,
                            credential_key_id: row.get(7)?,
                        },
                    })
                })?);
            }
        }
        transaction.commit()?;
        Ok(records)
    }

    pub fn mark_delivered(&mut self, ids: &[i64], delivered_at: u64) -> Result<(), GitAiError> {
        let delivered_at = as_sql_timestamp(delivered_at)?;
        let transaction = self.connection.transaction()?;
        for id in ids {
            transaction.execute(
                "UPDATE security_finding_queue
                    SET delivered_at = ?1, processing_started_at = NULL, last_error_class = NULL
                  WHERE id = ?2 AND delivered_at IS NULL",
                params![delivered_at, id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_failed(
        &mut self,
        ids: &[i64],
        failure: SecurityFindingFailureClass,
        failed_at: u64,
    ) -> Result<(), GitAiError> {
        let failed_at = as_sql_timestamp(failed_at)?;
        let transaction = self.connection.transaction()?;
        for id in ids {
            let attempts = transaction.query_row(
                "SELECT attempts FROM security_finding_queue WHERE id = ?1",
                params![id],
                |row| row.get::<_, i64>(0),
            )?;
            let retry_delay =
                FIRST_RETRY_DELAY_SECS.saturating_mul(1_u64 << attempts.clamp(0, 5) as u32);
            transaction.execute(
                "UPDATE security_finding_queue
                    SET attempts = attempts + 1,
                        next_retry_at = ?1,
                        processing_started_at = NULL,
                        last_error_class = ?2
                  WHERE id = ?3 AND delivered_at IS NULL",
                params![
                    failed_at.saturating_add(retry_delay as i64),
                    failure.as_str(),
                    id,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn as_sql_timestamp(value: u64) -> Result<i64, GitAiError> {
    i64::try_from(value)
        .map_err(|_| GitAiError::Generic("security finding timestamp is invalid".to_string()))
}

fn validate_binding(binding: &EvidenceDeliveryBinding) -> Result<(), GitAiError> {
    for value in [
        binding.tenant_id.as_str(),
        binding.repository_id.as_str(),
        binding.repository_url.as_str(),
        binding.api_base_url.as_str(),
        binding.credential_key_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 2_048 {
            return Err(GitAiError::Generic(
                "security finding delivery binding is invalid".to_string(),
            ));
        }
    }
    Ok(())
}
