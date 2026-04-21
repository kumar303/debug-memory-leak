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
    ps -eo pid,ppid,rss,pmem,comm -r \
      | head -31 \
      | tail -30 \
      | awk '{ rss_mb = $3/1024; printf "%-8s %-8s %10.1f %6s  %s\n", $1, $2, rss_mb, $4, $5 }'

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
      timeout 15 code --status 2>&1 || printf "(code --status timed out or failed)\n"
    else
      printf "('code' not in PATH)\n"
    fi

    # ╭──────────────────────────────────────────────╮
    # │ 7. Process tree snapshot (pstree style)      │
    # ╰──────────────────────────────────────────────╯
    section "PROCESS TREE (Code descendants)"
    if command -v pstree &>/dev/null; then
      for cpid in $(pgrep -if 'Code Helper.app' | head -3); do
        printf "── tree for PID %s ──\n" "$cpid"
        pstree "$cpid" 2>/dev/null || true
      done
    else
      printf "(pstree not installed — brew install pstree)\n"
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

  } 2>&1 | tee -a "$LOG"

  sleep "$INTERVAL_SECS"
done
