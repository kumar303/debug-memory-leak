# debug-memory-leak

Tools for diagnosing gradual memory leaks on a **macOS** developer workstation,
with a focus on VS Code (`code`), its extensions, and the
language servers they spawn (tsserver, eslintServer, graphql-language-server…).

The intended symptom is:

> "My Mac's memory fills up after a day or two and swap grows into the GBs,
> even though no single process looks suspicious at any given moment."

The approach is simple: take detailed memory snapshots on a fixed interval,
leave it running for a day or more, then analyze the resulting log to find
processes whose RSS grows monotonically over time.

## Requirements

- **macOS** — the snapshot script uses macOS-only tools (`vm_stat`, `sysctl`,
  `memory_pressure`, `vmmap`, `lsof`, `/bin/ps` with BSD flags). It will not
  work on Linux without modification.
- **`code` on `PATH`** — VS Code's CLI is invoked as `code --status` to capture
  its internal process and memory diagnostics. Install via VS Code's
  `Shell Command: Install 'code' command in PATH` command.
- **Python 3** — the analyzer is a single standalone Python 3 script (no
  dependencies).
- **bash** — the monitor is a bash script. No other shells are supported.

No `sudo` is needed. You only get visibility into your own processes, which is
exactly what we want — the leak is virtually always in user-space processes.

## Files

| File               | Purpose                                                       |
| ------------------ | ------------------------------------------------------------- |
| `mem-monitor.sh`   | Long-running snapshot collector. Writes to `mem-monitor.log`. |
| `mem-monitor.log`  | Rolling log of snapshots (appended to — safe to restart).     |
| `analyze-leaks.py` | Parses `mem-monitor.log` and pinpoints leakers.               |
| `heap-snapshots/`  | Auto-captured artefacts when `pi` RSS exceeds a threshold.    |

## Quickstart

```bash
# 1. Start collecting snapshots (runs in foreground, Ctrl-C to stop).
./mem-monitor.sh

# 2. Leave it running for a day or more. You can close the terminal if you
#    started it with nohup / background (see below). Restarts append to the
#    same log.

# 3. Analyze.
python3 analyze-leaks.py
```

The analyzer prints:

- **System-wide memory pressure timeline** — free/compressed/swap/pageouts
  over time. This tells you _when_ the leak started.
- **Top 25 absolute growers** — processes whose RSS increased the most
  (MB gained over their lifetime).
- **Top 25 rate-based leakers** — by `MB/hour` linear regression slope.
- **Growth by category** — aggregated across all tsservers, extension hosts,
  renderers, eslintServers, pi agents, etc.
- **Deep dive on the #1 suspect** — full trajectory + cmdline.
- **Cmdline-signature groups** — when identical scripts run under multiple
  PIDs, they're grouped so you see the pattern.
- **Actionable recommendations** — ordered by impact, with exact fixes
  (close this window, restart that language server, disable that extension).

## What the monitor captures per snapshot

Every 5 minutes (configurable via `INTERVAL_SECS` in the script):

1. **System memory** — `vm_stat` breakdown (free/active/inactive/wired/
   compressed/purgeable), swap usage, memory pressure.
2. **Top 30 processes by RSS** — PID, PPID, RSS(MB), `%MEM`, and the **full**
   command line (not truncated `comm`).
3. **VS Code / Electron processes** — every Code/Electron process with full
   cmdline, plus a total RSS sum.
4. **pi / node processes** — same, filtered to `pi-coding-agent`,
   `pi-monorepo`, or generic `node`.
5. **Shell / terminal children under Code** — catches integrated-terminal
   subprocesses (`pi`, long-running `node`, etc.).
6. **`code --status`** — VS Code's built-in per-process + workspace stats.
7. **Process tree** — custom tree built from `ps` (not `pstree`, which is
   blocked by Santa at Shopify) showing Code descendants with RSS at each
   level.
8. **FD counts** for top RSS processes — spots FD leaks, which often
   accompany memory leaks.
9. **Swap trend markers** — cumulative pageouts counter.
10. **Heap-snapshot trigger** — see below.

## Heap-snapshot trigger (for pi specifically)

When any `pi` process exceeds `PI_HEAP_THRESHOLD_MB` (default **1500 MB**),
the monitor automatically:

- Saves `pi-<PID>-<TIMESTAMP>.context.txt` — cmdline + parent chain
- Saves `pi-<PID>-<TIMESTAMP>.vmmap-summary.txt` — macOS region breakdown
  (distinguishes native heap vs JS heap vs reserved VM)
- Saves `pi-<PID>-<TIMESTAMP>.lsof.txt` — open files, loaded `.node` native
  addons, pipes
- Sends `SIGUSR1` to the pi Node process, which opens Node's inspector port
- Captures the listening TCP port in `pi-<PID>-<TIMESTAMP>.inspector-port.txt`
- Writes a `README.md` next to the artefacts with step-by-step instructions
  for grabbing a real JS `.heapsnapshot` via Chrome DevTools at
  `chrome://inspect → localhost:9229`.

Cooldown is 1 hour per PID so restarts / repeated threshold crossings don't
flood `heap-snapshots/`.

Override the threshold:

```bash
PI_HEAP_THRESHOLD_MB=100 ./mem-monitor.sh    # fire early (for testing)
PI_HEAP_THRESHOLD_MB=2500 ./mem-monitor.sh   # only when clearly leaking
```

## Running in the background

The script runs in the foreground by default and prints live output via
`tee`. To run detached:

```bash
nohup ./mem-monitor.sh &

# find it later
pgrep -fl mem-monitor.sh

# stop it
pkill -f mem-monitor.sh
```

You don't need `caffeinate` — if the Mac sleeps, the script pauses and
resumes. No leak happens during sleep anyway.

## Restarting doesn't lose data

`mem-monitor.sh` appends (`tee -a`, `>>`). Restarts add a new
`mem-monitor: started …` marker but preserve every prior snapshot. The
analyzer happily parses logs that span multiple runs.

To start fresh: `rm mem-monitor.log` before restarting, or pass a new path
as the first argument: `./mem-monitor.sh ./mem-monitor-day2.log`.

## Custom log location

```bash
./mem-monitor.sh /tmp/mem.log
python3 analyze-leaks.py /tmp/mem.log
```

## Debugging the monitor itself

Every non-zero command is reported (the script uses an `ERR` trap that
prints line number + failing command). Unexpected exits print
`[mem-monitor UNEXPECTED EXIT]`. For full xtrace of every command:

```bash
DEBUG=1 ./mem-monitor.sh
```

## Interpreting the results — common patterns

- **One tsserver at 1-2 GB, growing**: the workspace is too big or has too
  many open files. Run `TypeScript: Restart TS Server` in that window, or
  close the window. Each VS Code window spawns its own tsserver, so fewer
  windows = much less memory.
- **Multiple eslintServers over 500 MB each**: classic ESLint memory leak.
  Add broader `.eslintignore` rules, or disable the ESLint extension in
  workspaces where you're not actively linting.
- **Extension host growing but no single child accounts for it**: run
  `Developer: Show Running Extensions` in VS Code. Disable extensions
  in halves until the leak stops.
- **pi process growing unboundedly**: wait for the heap-snapshot trigger,
  then follow the README in `heap-snapshots/` to capture a `.heapsnapshot`
  in Chrome DevTools. Sort by **Retained Size**; retainer paths under
  `~/.pi/extensions/` or `~/.pi/agent/extensions/` name the leaking
  extension.
- **Swap grows but no individual process looks big**: look at the
  **category totals** in the analyzer — sometimes 20 smallish processes
  (e.g. Chrome tabs, tsservers across many windows) add up to the leak.

## For AI agents

See [AGENTS.md](./AGENTS.md).

## License

[WTFPL](./LICENSE)
