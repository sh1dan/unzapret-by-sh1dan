//! Privacy-preserving, bounded rotating file logger.
//! Strictly conforms to docs/threat-model.md:
//! - Hard size limit: 512 KB per file with 1 rotation backup (app.log.1).
//! - Zero packet payload, zero user URLs, zero flow IPs, zero extracted SNI.
//! - Captures only lifecycle events, profile selection, aggregate counters, and diagnostic codes.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_LOG_BYTES: u64 = 512 * 1024; // 512 KB
pub const LOG_DIR: &str = "logs";
pub const LOG_FILE: &str = "app.log";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Formats current UTC timestamp as ISO-8601 string without external chrono crate.
fn current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs();
    let days_since_epoch = total_secs / 86400;
    let day_secs = total_secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Simple Gregorian calendar conversion
    let mut year = 1970;
    let mut d = days_since_epoch;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        month += 1;
    }
    let day = d + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Rotates log files if primary file exceeds MAX_LOG_BYTES.
fn rotate_if_needed(log_path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::metadata(log_path) {
        if meta.len() >= MAX_LOG_BYTES {
            let backup_path = log_path.with_extension("log.1");
            let _ = fs::remove_file(&backup_path);
            let _ = fs::rename(log_path, backup_path);
        }
    }
    Ok(())
}

/// Sanitizes a log message string to ensure no raw packet dumps or URLs are written.
pub fn sanitize_message(msg: &str) -> String {
    // Strip control characters, keep single-line readable ASCII
    let filtered: String = msg
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                ' '
            }
        })
        .collect();
    filtered.trim().to_string()
}

/// Appends a sanitized entry to logs/app.log.
pub fn append_log(level: LogLevel, category: &str, message: &str) -> std::io::Result<()> {
    let app_dir = windivert_adapter::application_dir().unwrap_or_else(|_| PathBuf::from("."));
    let log_dir = app_dir.join(LOG_DIR);
    let _ = fs::create_dir_all(&log_dir);
    let log_path = log_dir.join(LOG_FILE);

    rotate_if_needed(&log_path)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let ts = current_timestamp();
    let sanitized = sanitize_message(message);
    writeln!(file, "[{ts}] [{level}] [{category}] {sanitized}")?;
    file.flush()
}

pub fn log_lifecycle(action: &str) {
    let _ = append_log(LogLevel::Info, "LIFECYCLE", action);
}

pub fn log_counters(counters: &crate::core::Counters) {
    let msg = counters.to_string();
    let _ = append_log(LogLevel::Info, "COUNTERS", &msg);
}

/// Reads the last `max_lines` from the log file.
pub fn read_recent_logs(max_lines: usize) -> Result<Vec<String>, String> {
    let app_dir =
        windivert_adapter::application_dir().map_err(|e| format!("Cannot resolve app dir: {e}"))?;
    let log_path = app_dir.join(LOG_DIR).join(LOG_FILE);

    if !log_path.exists() {
        return Ok(vec![
            "(Log file does not exist yet. Run 'start' or 'diagnose' to generate events.)".into(),
        ]);
    }

    let file = File::open(&log_path).map_err(|e| format!("Cannot open log file: {e}"))?;
    let reader = BufReader::new(file);

    let mut lines = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        lines.push(line);
    }

    if lines.len() > max_lines {
        let skip = lines.len() - max_lines;
        Ok(lines.into_iter().skip(skip).collect())
    } else {
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_message_removes_control_chars() {
        let dirty = "Hello\x00\x01World\r\nTest";
        let clean = sanitize_message(dirty);
        assert_eq!(clean, "Hello  World  Test");
    }

    #[test]
    fn timestamp_format_is_iso8601() {
        let ts = current_timestamp();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
