use std::fmt::Write;

/// One metric sample emitted by the collector.
pub struct Sample {
    pub tag: String,
    pub value: f64,
}

/// Escape tag values for Influx line protocol:
/// commas, spaces, and equals must be escaped with backslash.
fn escape_tag_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            ',' | ' ' | '=' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Formats samples into Influx line protocol.
/// Output is one line per sample and includes a timestamp.
pub fn format_payload(samples: &[Sample]) -> String {
    // CWE-665 fix: do NOT fall back to 0.
    // Prefer nanos; if unavailable, fall back to seconds * 1e9.
    let ts_ns = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| chrono::Utc::now().timestamp().saturating_mul(1_000_000_000));

    // Preallocate: rough baseline, reduces allocations.
    let mut out = String::with_capacity(samples.len().saturating_mul(64));

    for s in samples {
        // CWE-20 fix: escape tag values for line protocol safety.
        let tag = escape_tag_value(&s.tag);

        // Influx line protocol:
        // measurement,tag_key=tag_value field_key=field_value timestamp
        // We use a single float field called "value".
        let _ = writeln!(&mut out, "win_perf,tag={} value={} {}", tag, s.value, ts_ns);
    }

    out
}
