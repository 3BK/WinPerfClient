# WinPerfClient — System Specification Narrative (Short) + Resource/Performance Estimates

## 1) Purpose and Scope
WinPerfClient is a lightweight Windows host-side metrics collector that samples configured Windows Performance Counters (PDH) on a fixed interval and writes newline-delimited metric records to a Windows Named Pipe for downstream forwarding (e.g., to VictoriaMetrics by a separate relay/forwarder). 
The client prioritizes low overhead, resilience to transient PDH/IPC failures, and audit-friendly operational visibility through a Windows Event Log-backed logging pipeline. 

## 2) System Context and Boundaries
### In-scope
- Periodic PDH sampling using a single PDH query and multiple counter handles. 
- Payload formatting into a line-oriented text format (one line per metric sample). 
- Emission to a local Windows Named Pipe using Tokio’s named pipe client API. 
- Audit logging via `log` crate integration and a Windows Event Log backend. 

### Out-of-scope
- Network delivery to VictoriaMetrics (performed by the relay/forwarder that reads from the pipe). 
- Durable buffering, retry-at-scale, and backpressure policies beyond the local IPC boundary (belongs to the relay/forwarder). 

## 3) Architecture Narrative (High-Level)
### 3.1 Startup Sequence
1. Initialize the audit logger and set the active log level (Info/Debug/Trace, etc.). 
2. Load and parse `config.toml` into:
   - `interval_seconds`
   - `pipe_name`
   - `metrics[]` entries `{ tag, path }` 
3. Open a PDH query (`PdhOpenQueryW`) and register counter handles (`PdhAddCounterW`) for each configured metric path. 
4. Establish steady-state collection loop driven by `tokio::time::interval`. 

### 3.2 Steady-State Data Flow (Per Interval Tick)
1. Collect PDH query data once per tick (`PdhCollectQueryData`).   
2. For each counter:
   - Read and format the counter value as `double` (`PdhGetFormattedCounterValue` with `PDH_FMT_DOUBLE`).
   - Skip invalid values based on PDH status/CStatus checks (robustness against transient PDH states). 
3. Format output as newline-delimited lines:
   - `win_perf,tag=<tag> value=<float> <timestamp>\n` 
4. Open/connect to the named pipe and write the payload bytes. 

### 3.3 Named Pipe Operational Behavior
Tokio named pipe clients commonly encounter:
- `ErrorKind::NotFound` when the pipe server (relay) is not present.
- `ERROR_PIPE_BUSY` when the server exists but is busy; the recommended client behavior is to sleep briefly and retry. 

## 4) Memory Protection and Safety Posture
### 4.1 Process-Level Memory Protection (Build/Link Hardening)
The project’s `.cargo/config.toml` and release profile indicate intent to harden the binary:
- **Control Flow Guard (CFG)** via linker flags (e.g., `/GUARD:CFG`) and related options. 
- **Static CRT linking** (`+crt-static`) to reduce runtime dependencies and simplify deployment footprint.
- Release profile choices that typically reduce introspection surface and improve determinism:
  - `lto = true`, `codegen-units = 1`, `strip = true`, and `panic = "abort"`. 

### 4.2 Language/Runtime Safety
- The client uses Rust’s ownership/borrowing model for general memory safety and structured resource cleanup patterns. 
- PDH query lifetime is controlled through RAII-style cleanup (close on scope exit) in the guard module. 
- Windows FFI usage (PDH and Event Log) is isolated to explicit `unsafe` call sites; correctness relies on validating return codes and maintaining pointer lifetimes through the call boundary. 

## 5) Performance and Resource Demand Estimates (Scenarios)
> These are order-of-magnitude sizing estimates for planning and comparison. Actual performance depends on counter complexity, host load, logging level, and named pipe server behavior. 

### 5.1 Common Cost Drivers
- PDH calls per tick:
  - 1× `PdhCollectQueryData` per interval. 
  - N× `PdhGetFormattedCounterValue` (N = number of counters). 
- Formatting cost:
  - N lines appended into a single payload string.   
- IPC cost:
  - Open/connect + write to named pipe once per interval (with possible retry on NotFound/BUSY). 

### 5.2 Throughput Model (Payload Size)
Each metric emits one text line similar to:
`win_perf,tag=<tag> value=<float> <timestamp>\n` 

A practical per-line size range (tag/value/timestamp dependent) is typically ~60–120 bytes/line (planning heuristic derived from the literal line format). 

### 5.3 Scenario Estimates

#### Scenario A — 10 metrics every 10 seconds
- **Sampling rate:** ~1 metric/sec average. 
- **PDH calls per second:** ~1 formatted read/sec + 0.1 collects/sec (one collect per 10s). 
- **Pipe throughput:** ~0.06–0.12 KB/sec average (10 lines/10s). 
- **CPU:** typically “near-zero” on modern systems (well below 0.1% of a single core in steady-state), dominated by syscall overhead rather than compute. 
- **Memory:** working set primarily driven by the runtime and libraries; per-interval transient buffers are tiny (tens of KB). 

#### Scenario B — 100 metrics every 10 seconds (your target baseline)
- **Sampling rate:** ~10 metrics/sec average. 
- **PDH calls per second:** ~10 formatted reads/sec + 0.1 collects/sec. 
- **Pipe throughput:** ~0.6–1.2 KB/sec average (100 lines/10s). 
- **CPU (steady state):** typically ~0.1%–0.5% of a single core; conservative upper bound ~1% if counters are expensive or if retries/logging increase overhead. 
- **Memory:** payload + sample vectors remain modest; working set still dominated by runtime/linked dependencies; transient per-interval allocations generally <1 MB (often far less) at this size. 

#### Scenario C — 1,000 metrics every 10 seconds (stress-planning)
- **Sampling rate:** ~100 metrics/sec average. 
- **PDH calls per second:** ~100 formatted reads/sec + 0.1 collects/sec. 
- **Pipe throughput:** ~6–12 KB/sec average (1,000 lines/10s). 
- **CPU:** likely rises into low single-digit % of a core depending on counter complexity and system load; PDH formatting cost becomes the dominant factor. 
- **Memory:** still manageable, but allocation churn may become more noticeable; consider buffer reuse and pre-escaped tags if scaling beyond hundreds of counters. 

### 5.4 Failure-Mode Performance Considerations
- If the pipe server is down, client open attempts can fail with NotFound; if the pipe server is busy, ERROR_PIPE_BUSY can occur; correct client behavior is bounded retry with sleep to avoid busy-wait CPU spikes. 
- Excessive logging can become a cost center during repeated failures; the audit logger is designed to support configurable verbosity (e.g., Debug/Trace for troubleshooting). 

## 6) Operational Notes (Short)
- Ensure the named pipe relay maintains availability so clients do not frequently encounter NotFound errors; Tokio documentation describes the need for servers to keep at least one instance available to avoid sporadic client failures. 
- Use Info-level logging in production and enable Debug/Trace only during troubleshooting to minimize event volume and overhead. 

## 7) Summary (Sizing Snapshot)
- 10 metrics / 10s: negligible CPU; ~0.06–0.12 KB/s pipe output. 
- 100 metrics / 10s: ~0.1–0.5% of a core typical; ~0.6–1.2 KB/s pipe output. 
- 1,000 metrics / 10s: low single-digit % CPU possible; ~6–12 KB/s pipe output; consider buffer reuse if scaling. 
- Memory protection: CFG/link hardening intent and release stripping/LTO; Rust safety + RAII cleanup patterns; explicit `unsafe` FFI call boundaries with validation. 
