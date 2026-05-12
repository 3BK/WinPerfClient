use zeroize::Zeroize;

#[derive(Zeroize)]
pub struct Sample {
    pub tag: String,
    pub value: f64,
}

pub fn format_payload(samples: &[Sample]) -> String {
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    samples.iter()
        .map(|s| format!("win_perf,tag={} value={} {}\n", s.tag, s.value, ts))
        .collect()
}
