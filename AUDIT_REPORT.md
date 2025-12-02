# AUDIT_REPORT.md

## 1. Vulnerability Analysis

### A. Unbounded Memory Growth (DoS)
- **Location**: `fetch_external_blocklist` function.
- **Issue**: The code uses `requests.get(url).text.splitlines()`.
- **Risk**: If an attacker (or a compromised source) serves a multi-gigabyte file, the agent attempts to load the entire content into RAM before splitting it. This will trigger the OOM Killer, crashing the agent.
- **Mitigation**: Stream the response using `iter_lines()` and enforce a hard limit on the number of lines or total bytes processed.

### B. Blocking I/O & Process Hangs
- **Location**: `subprocess.run` calls (e.g., `unbound-checkconf`, `systemctl`).
- **Issue**: No `timeout` parameter is specified.
- **Risk**: If the subprocess hangs (e.g., waiting for a lock or resource), the entire agent freezes indefinitely.
- **Mitigation**: Add `timeout=30` (or appropriate value) to all `subprocess.run` calls.

### C. Lack of Circuit Breakers
- **Location**: `main_loop`.
- **Issue**: If the API is down or returning errors, the loop retries every `POLL_INTERVAL` (60s). While not a tight loop, persistent failures are not handled gracefully (no backoff).
- **Risk**: In a tight failure loop (if `POLL_INTERVAL` were smaller or logic changed), this could flood logs or the network.
- **Mitigation**: Implement exponential backoff for repeated failures.

## 2. Attack Scenario Simulation (100k queries/sec)
*Note: The agent itself manages DNS servers but doesn't process DNS queries directly in the Python loop. However, the "attack" here is interpreted as high load on the agent's inputs (API/Blocklists).*

- **Scenario**: The agent receives a configuration with 50 external blocklist URLs, each pointing to a 1GB file.
- **Current Behavior**: The agent iterates through the URLs. On the first 1GB file, `requests.get` attempts to allocate ~1GB+ RAM for the string. If the system has limited RAM (common in VPS), the process is killed immediately.
- **Hardened Behavior**: The agent streams each file. It reads line by line. If a file exceeds a defined limit (e.g., 10MB or 100k rules), it aborts that specific download, logs a warning, and proceeds to the next. Memory usage remains constant and low.

## 3. Critical Refactoring Summary
- **Refactoring**: `sentinela-agent.py`
- **Fixes**:
    - Streaming downloads with size limits.
    - Timeouts on all external calls (HTTP & Subprocess).
    - Specific exception handling.
