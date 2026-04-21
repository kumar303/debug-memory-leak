#!/usr/bin/env bash
#
# mem-monitor.sh — Continuous memory‐leak hunter
#
# Writes timestamped snapshots to a rolling log.
# Focus: VS Code (code), its children (terminals, extensions, pi), and
# any other process consuming significant RSS.
#
# Usage:
#   ./mem-monitor.sh              # logs to ./mem-monitor.log
#   ./mem-monitor.sh /tmp/mem.log # custom log path
#
# Stop with Ctrl-C. Safe to leave running for days.

# Deliberately NOT using `set -e` / `pipefail`:
# many pipelines here (ps | head, grep | sort) legitimately produce SIGPIPE
# or empty results, and we don't want that to kill the monitor.
# We DO want to see every error, so:
#   - unset vars are errors (set -u)
#   - xtrace can be toggled via DEBUG=1
#   - an ERR trap prints the failing line
#   - an EXIT trap reports unexpected exits
set -u

[[ "${DEBUG:-0}" == "1" ]] && set -x

LOG="${1:-$(dirname "$0")/mem-monitor.log}"
INTERVAL_SECS=300  # 5 minutes — tune down to 60 for faster capture

# Heap-snapshot trigger config — auto-capture when pi RSS exceeds threshold.
PI_HEAP_THRESHOLD_MB="${PI_HEAP_THRESHOLD_MB:-1500}"
HEAP_COOLDOWN_SECS="${HEAP_COOLDOWN_SECS:-3600}"
HEAP_DIR="$(dirname "$0")/heap-snapshots"
HEAP_STATE_FILE="$HEAP_DIR/.triggered.state"
mkdir -p "$HEAP_DIR"
touch "$HEAP_STATE_FILE"

# ── helpers ──────────────────────────────────────────────────────────────────

banner() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S %z')"
  printf '\n%s\n' "================================================================================"
  printf '=== SNAPSHOT  %s\n' "$ts"
  printf '%s\n\n' "================================================================================"
}

section() {
  printf '\n--- %s ---\n\n' "$1"
}

human_mb() {
  # stdin: RSS in KB → stdout: MB with 1 decimal
  awk '{ printf "%.1f MB\n", $1/1024 }'
}

# ── main loop ────────────────────────────────────────────────────────────────

echo "mem-monitor: logging to $LOG every ${INTERVAL_SECS}s  (Ctrl-C to stop)"
echo "mem-monitor: PID $$  — kill with:  kill $$"
echo "mem-monitor: started $(date '+%Y-%m-%d %H:%M:%S %z')" | tee -a "$LOG"

# ── Error reporting ─────────────────────────────────────────────────────────
# Any command that returns non-zero is reported (but doesn't kill the script).
# Any unexpected exit is reported loudly.
EXPECTED_EXIT=0

on_err() {
  local exit_code=$?
  local line=${BASH_LINENO[0]:-?}
  local cmd=${BASH_COMMAND:-?}
  printf '\n[mem-monitor ERROR] exit=%s line=%s cmd=%q\n' \
    "$exit_code" "$line" "$cmd" | tee -a "$LOG" >&2
}

on_exit() {
  local code=$?
  if [[ $EXPECTED_EXIT -eq 1 ]]; then
    printf '\nmem-monitor: stopped cleanly at %s (exit %s)\n' "$(date)" "$code" | tee -a "$LOG"
  else
    printf '\n[mem-monitor UNEXPECTED EXIT] code=%s at %s\n' \
      "$code" "$(date)" | tee -a "$LOG" >&2
  fi
}

trap on_err ERR
trap on_exit EXIT
trap 'EXPECTED_EXIT=1; exit 0' INT TERM

while true; do
  {
    banner

    # ╭──────────────────────────────────────────────╮
    # │ 1. System‐wide memory & swap (vm_stat + sysctl)│
    # ╰──────────────────────────────────────────────╯
    section "SYSTEM MEMORY (vm_stat + sysctl)"

    page_size=$(sysctl -n hw.pagesize)
    total_mem_bytes=$(sysctl -n hw.memsize)
    total_mem_mb=$(( total_mem_bytes / 1024 / 1024 ))

    vm_stat_out="$(vm_stat)"
    extract() { echo "$vm_stat_out" | awk -v pat="$1" '$0 ~ pat { gsub(/\./,"",$NF); print $NF }'; }

    free_pages=$(extract "Pages free")
    active_pages=$(extract "Pages active")
    inactive_pages=$(extract "Pages inactive")
    speculative_pages=$(extract "Pages speculative")
    wired_pages=$(extract "Pages wired")
    compressed_pages=$(extract "Pages occupied by compressor")
    purgeable_pages=$(extract "Pages purgeable")
    swap_used_pages=$(extract "Swapouts")  # cumulative, but useful as a trend signal

    to_mb() { echo $(( ($1 * page_size) / 1024 / 1024 )); }

    printf "Total physical RAM : %s MB\n" "$total_mem_mb"
    printf "Free               : %s MB\n" "$(to_mb "${free_pages:-0}")"
    printf "Active             : %s MB\n" "$(to_mb "${active_pages:-0}")"
    printf "Inactive           : %s MB\n" "$(to_mb "${inactive_pages:-0}")"
    printf "Speculative        : %s MB\n" "$(to_mb "${speculative_pages:-0}")"
    printf "Wired              : %s MB\n" "$(to_mb "${wired_pages:-0}")"
    printf "Compressed         : %s MB\n" "$(to_mb "${compressed_pages:-0}")"
    printf "Purgeable          : %s MB\n" "$(to_mb "${purgeable_pages:-0}")"

    # Swap usage via sysctl
    swap_info="$(sysctl vm.swapusage 2>/dev/null || true)"
    printf "\nSwap: %s\n" "$swap_info"

    # Memory pressure
    pressure="$(memory_pressure 2>/dev/null | head -1 || echo 'N/A')"
    printf "Memory pressure: %s\n" "$pressure"

    # ╭──────────────────────────────────────────────╮
    # │ 2. Top 30 processes by RSS                   │
    # ╰──────────────────────────────────────────────╯
    section "TOP 30 PROCESSES BY RSS"
    printf "%-8s %-8s %10s %6s  %s\n" "PID" "PPID" "RSS(MB)" "%MEM" "COMMAND"
    # Use `args` (full cmdline) instead of `comm` (truncated). Sort by RSS desc.
    ps -eo pid,ppid,rss,pmem,args \
      | awk 'NR>1 { cmd=""; for (i=5;i<=NF;i++) cmd=cmd" "$i;
                    printf "%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, cmd }' \
      | sort -k3 -rn \
      | head -30 \
      | awk -F'\t' '{ rss_mb=$3/1024; printf "%-8s %-8s %10.1f %6s  %s\n", $1, $2, rss_mb, $4, $5 }'

    # ╭──────────────────────────────────────────────╮
    # │ 3. All VS Code / Electron processes          │
    # ╰──────────────────────────────────────────────╯
    section "VS CODE / ELECTRON PROCESSES (full cmdline + RSS)"
    printf "%-8s %-8s %10s  %s\n" "PID" "PPID" "RSS(MB)" "CMDLINE"
    # Grab anything with "code" or "Electron" in the path/args
    ps -eo pid,ppid,rss,args \
      | grep -iE '(code|[Ee]lectron|[Cc]ode Helper)' \
      | grep -v 'grep' \
      | sort -k3 -rn \
      | awk '{ rss_mb=$3/1024; cmd=""; for(i=4;i<=NF;i++) cmd=cmd" "$i;
              printf "%-8s %-8s %10.1f  %s\n", $1, $2, rss_mb, cmd }' \
      || printf "(none found)\n"

    # Sum of VS Code RSS
    vscode_total_kb=$(ps -eo rss,comm | grep -iE '(code|Electron)' | grep -v grep \
      | awk '{s+=$1} END{print s+0}')
    printf "\n>> VS Code family total RSS: %s\n" "$(echo "$vscode_total_kb" | human_mb)"

    # ╭──────────────────────────────────────────────╮
    # │ 4. Pi agent / node processes                 │
    # ╰──────────────────────────────────────────────╯
    section "PI / NODE PROCESSES"
    printf "%-8s %-8s %10s  %s\n" "PID" "PPID" "RSS(MB)" "CMDLINE"
    ps -eo pid,ppid,rss,args \
      | grep -iE '(pi-coding-agent|pi-monorepo|/pi |node )' \
      | grep -v 'grep' \
      | sort -k3 -rn \
      | awk '{ rss_mb=$3/1024; cmd=""; for(i=4;i<=NF;i++) cmd=cmd" "$i;
              printf "%-8s %-8s %10.1f  %s\n", $1, $2, rss_mb, cmd }' \
      || printf "(none found)\n"

    # ╭──────────────────────────────────────────────╮
    # │ 5. Integrated terminal / shell children      │
    # ╰──────────────────────────────────────────────╯
    section "SHELL / TERMINAL CHILD PROCESSES (zsh, bash, fish under Code)"
    # Find VS Code's main PIDs, then look for shell children
    code_pids=$(ps -eo pid,comm | grep -iE '(code|Electron)' | grep -v grep | awk '{print $1}' | tr '\n' '|' | sed 's/|$//')
    if [[ -n "$code_pids" ]]; then
      printf "%-8s %-8s %10s  %s\n" "PID" "PPID" "RSS(MB)" "CMDLINE"
      ps -eo pid,ppid,rss,args \
        | awk -v pids="$code_pids" 'BEGIN{split(pids,a,"|"); for(i in a) p[a[i]]=1}
               $2 in p || $1 in p { rss_mb=$3/1024; cmd=""; for(i=4;i<=NF;i++) cmd=cmd" "$i;
               printf "%-8s %-8s %10.1f  %s\n", $1, $2, rss_mb, cmd }' \
        | sort -k3 -rn \
        | head -40
    else
      printf "(no VS Code processes found)\n"
    fi

    # ╭──────────────────────────────────────────────╮
    # │ 6. `code --status` (built-in diagnostics)    │
    # ╰──────────────────────────────────────────────╯
    section "VS CODE STATUS (code --status)"
    if command -v code &>/dev/null; then
      # macOS has no `timeout`; run in background and kill after N seconds.
      (
        code --status 2>&1 &
        cpid=$!
        ( sleep 15; kill -9 "$cpid" 2>/dev/null ) &
        watcher=$!
        wait "$cpid" 2>/dev/null
        kill "$watcher" 2>/dev/null
      ) || printf "(code --status failed)\n"
    else
      printf "('code' not in PATH)\n"
    fi

    # ╭──────────────────────────────────────────────╮
    # │ 7. Process tree snapshot (pstree style)      │
    # ╰──────────────────────────────────────────────╯
    section "PROCESS TREE (Code descendants, built from ps)"
    # pstree is blocked by Santa at Shopify — build our own tree from ps.
    # Find top-level Code processes (ppid is launchd or not-a-Code-process),
    # then recursively print children with indentation.
    # Space-separated (awk -v can't handle embedded newlines).
    code_roots=$(ps -eo pid,ppid,comm \
      | awk '/[Cc]ode|Electron/ && !/grep/ { print $1 }' \
      | tr '\n' ' ')
    if [[ -n "${code_roots// /}" ]]; then
      # Build a parent→children map once, then walk it.
      ps -eo pid,ppid,rss,comm \
        | awk -v roots="$code_roots" '
            BEGIN { n=split(roots, r, " "); for (i=1;i<=n;i++) if (r[i]!="") is_root[r[i]]=1 }
            NR>1 {
              pid=$1; ppid=$2; rss=$3;
              comm=""; for (i=4;i<=NF;i++) comm=comm" "$i;
              parent[pid]=ppid; rss_of[pid]=rss; comm_of[pid]=comm;
              children[ppid] = children[ppid] " " pid;
            }
            END {
              # Print each root and its descendants.
              for (rp in is_root) {
                # Skip if this root is itself a child of another root (avoid dupes).
                if (parent[rp] in is_root) continue;
                walk(rp, 0);
              }
            }
            function walk(pid, depth,   i, n, kids, k) {
              indent = "";
              for (i=0; i<depth; i++) indent = indent "  ";
              printf "%s%-6s %8.1f MB %s\n", indent, pid, rss_of[pid]/1024, comm_of[pid];
              n = split(children[pid], kids, " ");
              for (k=1; k<=n; k++) if (kids[k] != "") walk(kids[k], depth+1);
            }
          '
    else
      printf "(no Code processes found)\n"
    fi

    # ╭──────────────────────────────────────────────╮
    # │ 8. Open file descriptors (leak signal)       │
    # ╰──────────────────────────────────────────────╯
    section "FD COUNTS FOR TOP RSS PROCESSES"
    printf "%-8s %8s %10s  %s\n" "PID" "FDs" "RSS(MB)" "COMM"
    ps -eo pid,rss,comm -r | head -16 | tail -15 | while read -r pid rss comm; do
      fds=$(lsof -p "$pid" 2>/dev/null | wc -l || echo '?')
      rss_mb=$(echo "$rss" | awk '{printf "%.1f", $1/1024}')
      printf "%-8s %8s %10s  %s\n" "$pid" "$fds" "$rss_mb" "$comm"
    done

    # ╭──────────────────────────────────────────────╮
    # │ 9. Cumulative swap-out counter (trend)       │
    # ╰──────────────────────────────────────────────╯
    section "SWAP TREND MARKERS"
    sysctl vm.swapusage 2>/dev/null || true
    printf "Pageouts (cumulative): %s\n" "$(vm_stat | awk '/Pageouts/ {gsub(/\./,"",$NF); print $NF}')"

    # ╭───────────────────────────────────────────────╮
    # │ 10. Heap-snapshot trigger (pi over threshold)│
    # ╰────────────────────────────────────────────────╯
    section "HEAP SNAPSHOT TRIGGER (threshold: ${PI_HEAP_THRESHOLD_MB} MB)"
    # Find every `pi` process and its RSS.
    pi_candidates=$(ps -eo pid,rss,comm,args \
      | awk '($3 == "pi") || ($4 ~ /\/pi$|\/pi /) { print $1" "$2 }')
    if [[ -z "$pi_candidates" ]]; then
      printf "(no pi process found)\n"
    else
      now=$(date +%s)
      printf "%-8s %10s  %s\n" "PID" "RSS(MB)" "ACTION"
      while read -r pi_pid pi_rss_kb; do
        [[ -z "$pi_pid" ]] && continue
        pi_rss_mb=$(awk -v k="$pi_rss_kb" 'BEGIN{printf "%.0f", k/1024}')
        if (( pi_rss_mb < PI_HEAP_THRESHOLD_MB )); then
          printf "%-8s %10s  under threshold\n" "$pi_pid" "$pi_rss_mb"
          continue
        fi

        last=$(awk -v p="$pi_pid" '$1==p {print $2}' "$HEAP_STATE_FILE" | tail -1)
        last=${last:-0}
        age=$(( now - last ))
        if (( age < HEAP_COOLDOWN_SECS )); then
          printf "%-8s %10s  over threshold, cooling down (%ss ago)\n" \
            "$pi_pid" "$pi_rss_mb" "$age"
          continue
        fi

        ts=$(date '+%Y%m%d-%H%M%S')
        prefix="$HEAP_DIR/pi-${pi_pid}-${ts}"
        printf "%-8s %10s  TRIGGERING SNAPSHOT → %s.*\n" \
          "$pi_pid" "$pi_rss_mb" "$prefix"

        # a) Context: cmdline + parent chain
        {
          echo "# pi heap-snapshot trigger"
          echo "timestamp: $(date)"
          echo "pid: $pi_pid"
          echo "rss_mb: $pi_rss_mb"
          echo "threshold_mb: $PI_HEAP_THRESHOLD_MB"
          echo
          echo "## cmdline"
          ps -p "$pi_pid" -o args= 2>/dev/null || echo "(gone)"
          echo
          echo "## parent chain"
          cp=$pi_pid
          for _ in 1 2 3 4 5; do
            line=$(ps -p "$cp" -o pid,ppid,comm,args 2>/dev/null | tail -1)
            [[ -z "$line" ]] && break
            echo "  $line"
            cp=$(echo "$line" | awk '{print $2}')
            [[ "$cp" == "1" || "$cp" == "0" ]] && break
          done
        } > "${prefix}.context.txt" 2>&1

        # b) vmmap summary (macOS region breakdown — JS heap vs native)
        if command -v vmmap &>/dev/null; then
          if vmmap -summary "$pi_pid" > "${prefix}.vmmap-summary.txt" 2>&1; then
            echo "         saved ${prefix}.vmmap-summary.txt"
          else
            echo "         vmmap failed (may need 'Developer Tools' permission)"
          fi
        fi

        # c) lsof — captures loaded .node addons and open JS files
        if lsof -p "$pi_pid" > "${prefix}.lsof.txt" 2>&1; then
          echo "         saved ${prefix}.lsof.txt"
        fi

        # d) SIGUSR1 → Node opens its inspector port
        if kill -SIGUSR1 "$pi_pid" 2>/dev/null; then
          echo "         sent SIGUSR1 — Node inspector should now be listening"
          # Wait a beat, then try to capture the listening port
          sleep 1
          lsof -p "$pi_pid" -iTCP -sTCP:LISTEN -Pn 2>/dev/null \
            > "${prefix}.inspector-port.txt" || true
        else
          echo "         kill -SIGUSR1 failed (process gone?)"
        fi

        # e) README with instructions
        base="${prefix##*/}"
        cat > "${prefix}.README.md" <<EOF
# pi heap snapshot — $(date)

pi (PID $pi_pid) RSS was ${pi_rss_mb} MB (threshold ${PI_HEAP_THRESHOLD_MB} MB).

## Files
- \`${base}.context.txt\` — cmdline + parent chain
- \`${base}.vmmap-summary.txt\` — macOS region breakdown (native vs JS heap)
- \`${base}.lsof.txt\` — open files, native addons, pipes
- \`${base}.inspector-port.txt\` — TCP port Node is listening on

## Capture the JS heap snapshot
Node was signalled (SIGUSR1) to open its inspector.

1. Check \`${base}.inspector-port.txt\` — it'll show something like \`127.0.0.1:9229\`.
2. Open Chrome → \`chrome://inspect\` → Configure → add that host:port.
3. Under "Remote Target" click **inspect**.
4. DevTools → **Memory** → **Heap snapshot** → **Take snapshot**.
5. Save the \`.heapsnapshot\` file next to this README.
6. Sort by **Retained Size**; retainer paths under \`~/.pi/extensions/\` or
   \`~/.pi/agent/extensions/\` identify the leaking extension.

## Quick identify without DevTools
\`\`\`bash
grep -E '\.pi/(agent/)?extensions/' ${base}.lsof.txt
\`\`\`

Shows every extension file pi has open — the leaker is usually the one
with the most open handles or the most \`.node\` native addons loaded.
EOF

        # f) Record trigger time in state file
        tmp=$(mktemp)
        awk -v p="$pi_pid" '$1 != p' "$HEAP_STATE_FILE" > "$tmp"
        echo "$pi_pid $now" >> "$tmp"
        mv "$tmp" "$HEAP_STATE_FILE"
      done <<< "$pi_candidates"
    fi

  } 2>&1 | tee -a "$LOG"

  sleep "$INTERVAL_SECS"
done
