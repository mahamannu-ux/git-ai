//! Controlled, dry-run-first replay of quarantined telemetry rows.

use crate::metrics::db::{MetricEvidenceFamily, MetricsDatabase, QuarantineBackfillRequest};

#[derive(Debug, PartialEq, Eq)]
struct ParsedBackfillArgs {
    request: QuarantineBackfillRequest,
    apply: bool,
}

fn usage() -> &'static str {
    "git-ai metrics-backfill --repository <canonical-url> \
     --family <generation-session|commit-note> --from <unix-seconds> \
     --until <unix-seconds> [--max-rows <1..1000>] [--apply]"
}

fn parse_args(args: &[String]) -> Result<ParsedBackfillArgs, String> {
    let mut repository_url = None;
    let mut evidence_family = None;
    let mut occurred_from = None;
    let mut occurred_until = None;
    let mut max_rows = 1000usize;
    let mut apply = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--repository" if index + 1 < args.len() => {
                repository_url = Some(args[index + 1].clone());
                index += 2;
            }
            "--family" if index + 1 < args.len() => {
                evidence_family = Some(match args[index + 1].as_str() {
                    "generation-session" => MetricEvidenceFamily::GenerationSession,
                    "commit-note" => MetricEvidenceFamily::CommitNote,
                    _ => return Err("family must be generation-session or commit-note".to_string()),
                });
                index += 2;
            }
            "--from" if index + 1 < args.len() => {
                occurred_from = Some(
                    args[index + 1]
                        .parse::<u64>()
                        .map_err(|_| "--from must be non-negative Unix seconds".to_string())?,
                );
                index += 2;
            }
            "--until" if index + 1 < args.len() => {
                occurred_until = Some(
                    args[index + 1]
                        .parse::<u64>()
                        .map_err(|_| "--until must be non-negative Unix seconds".to_string())?,
                );
                index += 2;
            }
            "--max-rows" if index + 1 < args.len() => {
                max_rows = args[index + 1]
                    .parse::<usize>()
                    .map_err(|_| "--max-rows must be an integer".to_string())?;
                index += 2;
            }
            "--apply" => {
                apply = true;
                index += 1;
            }
            "--help" | "-h" => return Err(usage().to_string()),
            option => return Err(format!("unknown or incomplete argument: {option}")),
        }
    }
    Ok(ParsedBackfillArgs {
        request: QuarantineBackfillRequest {
            repository_url: repository_url.ok_or_else(|| "--repository is required".to_string())?,
            evidence_family: evidence_family.ok_or_else(|| "--family is required".to_string())?,
            occurred_from: occurred_from.ok_or_else(|| "--from is required".to_string())?,
            occurred_until: occurred_until.ok_or_else(|| "--until is required".to_string())?,
            max_rows,
        },
        apply,
    })
}

pub fn handle_metrics_backfill(args: &[String]) {
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("metrics-backfill: {error}");
            eprintln!("Usage: {}", usage());
            return;
        }
    };
    let db = match MetricsDatabase::global() {
        Ok(db) => db,
        Err(error) => {
            eprintln!("metrics-backfill: failed to open metrics database: {error}");
            return;
        }
    };
    let mut db = match db.lock() {
        Ok(db) => db,
        Err(error) => {
            eprintln!("metrics-backfill: failed to lock metrics database: {error}");
            return;
        }
    };
    let preview = match db.preview_quarantine_backfill(&parsed.request) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("metrics-backfill: invalid request: {error}");
            return;
        }
    };
    println!("mode={}", if parsed.apply { "apply" } else { "dry-run" });
    println!("matching_rows={}", preview.matching_rows);
    println!("selected_rows={}", preview.selected_rows);
    println!(
        "oldest_occurred_at={}",
        preview
            .oldest_occurred_at
            .map_or("none".to_string(), |value| value.to_string())
    );
    println!(
        "newest_occurred_at={}",
        preview
            .newest_occurred_at
            .map_or("none".to_string(), |value| value.to_string())
    );
    if !parsed.apply {
        println!("queue_changes=none");
        println!("next=confirm a matching active server authorization, then rerun with --apply");
        return;
    }
    match db.apply_quarantine_backfill(&parsed.request, true, current_unix_ts()) {
        Ok(result) => println!("requeued_rows={}", result.selected_rows),
        Err(error) => eprintln!("metrics-backfill: apply failed: {error}"),
    }
}

fn current_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_backfill_parser_defaults_to_dry_run_and_requires_complete_scope() {
        let args = [
            "--repository",
            "https://github.com/example/repo",
            "--family",
            "generation-session",
            "--from",
            "100",
            "--until",
            "200",
        ]
        .map(str::to_string);
        let parsed = parse_args(&args).unwrap();
        assert!(!parsed.apply);
        assert_eq!(parsed.request.max_rows, 1000);
        assert!(parse_args(&["--apply".to_string()]).is_err());
    }
}
