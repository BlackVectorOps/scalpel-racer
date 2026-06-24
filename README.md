
```text
   _____ _________    __    ____  ________
  / ___// ____/   |  / /   / __ \/ ____/ /
  \__ \/ /   / /| | / /   / /_/ / __/ / /
 ___/ / /___/ ___ |/ /___/ ____/ /___/ /___
/____/\____/_/  |_/_____/_/   /_____/_____/
```

# Scalpel Racer

> **A high-precision race-condition testing framework.**

![Go Version](https://img.shields.io/badge/go-1.25%2B-blue)
![Strategies](https://img.shields.io/badge/strategies-h1%20%7C%20h2%20%7C%20h3-orange)
![Status](https://img.shields.io/badge/status-active-green)

Scalpel Racer finds and exploits race conditions in web applications by firing tightly-synchronized bursts of requests. It pairs an intercepting proxy (to capture traffic straight from your browser) with an interactive TUI and three timing strategies that squeeze out network jitter — down to kernel-level packet bunching on Linux.

---

## Why Scalpel Racer?

*   **Single-Packet Attack (H2):** Pre-sends every request's headers, then releases all the final `DATA` frames together — so the requests land in one window, not strung across the network.
*   **First-Sequence Sync (Linux):** Holds outbound packets in a `NetfilterQueue` and releases them as one burst for the tightest race window.
*   **Built-in interception:** HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) proxy with on-the-fly CA generation for HTTPS.
*   **Live analytics:** Groups responses by status code and body hash so an out-of-band result stands out immediately.

## Strategies

| Strategy | Transport | Technique |
| :--- | :--- | :--- |
| **h2** (default) | HTTP/2 | Single-packet attack — hold every stream's final `DATA` frame, release together. |
| **h1** | HTTP/1.1 | Staged send split at `{{SYNC}}` markers, released on a spin-barrier. |
| **h3** | HTTP/3 / QUIC | Hold the request body's final byte across streams, release together *(experimental)*. |

On Linux, **h1** and **h2** additionally bunch outbound packets via `NetfilterQueue` (First-Sequence Sync) when the target resolves to an IP — no extra configuration needed.

## Installation

Requires **Go 1.25+**.

```bash
git clone https://github.com/xkilldash9x/scalpel-racer.git
cd scalpel-racer
go build -o scalpel-racer ./cmd/scalpel-racer
```

## Usage

Scalpel Racer is an interactive TUI plus an intercepting proxy.

### 1. Start it

```bash
./scalpel-racer            # listens on :8080
./scalpel-racer -p 9090    # custom port
```

Flags: `-p <port>` listen port (default `8080`) · `-debug` verbose logging to `racer.log`.

### 2. Capture traffic

Point your browser (or Burp Suite) at `127.0.0.1:8080` for both HTTP and HTTPS, then trigger the request you want to test. It appears in the capture table.

### 3. Drive the TUI

| Key | Action |
| :--- | :--- |
| `↑`/`↓` (or `k`/`j`) | Navigate captures / results |
| `Enter` | Open the selected request in the editor |
| `Tab` | Cycle strategy (`h2` → `h1` → `h3`); the current one shows in the header |
| `Ctrl+S` | Editor: launch the race · Results: save a report |
| `Esc` | Back |
| `f` | Results: toggle outliers-only |
| `b` / `Enter` | Results: set baseline / suspect for diffing |
| `q` / `Ctrl+C` | Quit |

Bursts run at **20 concurrent requests**.

### Staged attacks (`{{SYNC}}`)

With the **h1** strategy, insert `{{SYNC}}` in the request body to split it into stages, e.g.:

```text
param=val&{{SYNC}}final=true
```

Every worker sends up to the marker, waits at the spin-barrier, then releases the remainder together — useful when the decisive state change rides on the last bytes.

## HTTPS interception

On first run, Scalpel Racer generates a CA under `~/.scalpel-racer/certs/`. Import `ca.pem` into your browser's trusted-root store to avoid certificate warnings. (Firefox keeps its own store, separate from the OS.)

## Architecture

| Package | Responsibility |
| :--- | :--- |
| `cmd/scalpel-racer` | Interactive TUI and entry point |
| `internal/proxy` | Intercepting proxy (TCP H1/H2 + QUIC H3) and dynamic CA |
| `internal/engine` | Race engines (`h1`/`h2`/`h3`) and the spin-barrier |
| `internal/packet` | Linux `NetfilterQueue` First-Sequence sync |

## Troubleshooting

*   **`permission denied` running `./scalpel-racer`** — the binary lacks the execute bit: `chmod +x ./scalpel-racer`.
*   **`address already in use`** — another process (or a prior instance) holds the port. Free it (`lsof -i :<port>` then `kill <pid>`) or pick another with `-p <port>`.
*   **Browser SSL warnings** — import `~/.scalpel-racer/certs/ca.pem` into the trusted-root store (Firefox has its own, separate from the OS).
*   **No requests captured** — confirm the browser/tool proxy points at `127.0.0.1:8080` (or your `-p` port) for **both** HTTP and HTTPS.
