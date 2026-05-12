# WinPerfClient — Deployment & Configuration Manual (Short)

> **Document purpose:** Deploy and configure `win-perf-client` as a lightweight Windows Performance Counter collector that emits newline-delimited metric lines to a Windows Named Pipe for forwarding to VictoriaMetrics by an external relay/forwarder. 

---

## 1. Overview

- `win-perf-client`:
  - Opens a PDH query and registers configured performance counters. 
  - On an interval, collects counter values, formats them into line-oriented text, and writes the payload to a **Named Pipe**. 
- A separate **relay/forwarder** is responsible for reading from the pipe and sending to VictoriaMetrics. (This manual covers only the client-side requirements and assumptions.) 

---

## 2. Artifacts & Files

- Binary: `win-perf-client.exe` (built in Release mode). 
- Runtime config file: `config.toml` in the working directory of the executable (or whichever directory you choose to run it from). 

Recommended directory layout:

- `C:\ProgramData\WinPerfClient\`
  - `win-perf-client.exe`
  - `config.toml`
  - (optional) wrapper scripts / service config

---

## 3. Prerequisites

### 3.1 Windows permissions / identity
- The running identity must be able to:
  - Read the required PDH counters (varies by counter set).
  - Connect and write to the configured Named Pipe path (ACLs on the pipe are enforced by the pipe server/relay). 

### 3.2 Named Pipe server availability
- The relay/forwarder should keep at least one server instance available so clients don’t fail with `NotFound` when connecting. 
- Client-side connection errors you should expect and handle operationally:
  - `std::io::ErrorKind::NotFound` (pipe server not up)
  - `ERROR_PIPE_BUSY` (server exists but is busy; retry) 

---

## 4. Configuration (`config.toml`)

### 4.1 Schema
Your client expects:

- `interval_seconds`: collection interval in seconds. 
- `pipe_name`: Named pipe path (recommend using the full Win32 pipe path). 
- `metrics`: array of counter definitions containing:
  - `tag`: a short identifier used in formatted output lines. 
  - `path`: the PDH counter path string passed into `PdhAddCounterW`. 

### 4.2 Example `config.toml`
```toml
interval_seconds = 10
pipe_name = "\\\\.\\pipe\\WinPerfRelay"

[[metrics]]
tag  = "cpu_total"
path = "\\Processor(_Total)\\% Processor Time"

[[metrics]]
tag  = "mem_available_mb"
path = "\\Memory\\Available MBytes"

[[metrics]]
tag  = "disk_c_free_mb"
path = "\\LogicalDisk(C:)\\Free Megabytes"
