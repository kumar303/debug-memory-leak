#!/usr/bin/env python3
"""
analyze-leaks.py — Parse mem-monitor.log and pinpoint memory leaks.

Builds per-PID RSS time series across all snapshots, then:
  1. Computes growth rate (MB/hr) via linear regression
  2. Classifies each process by workspace / extension / role
  3. Flags monotonically growing processes
  4. Correlates system-wide memory growth with swap/compression/pageouts
  5. Groups leakers by cmdline "signature" so we blame the right script

Usage:
  ./analyze-leaks.py [mem-monitor.log]
"""

from __future__ import annotations
import re
import sys
import statistics
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Optional


LOG_DEFAULT = Path(__file__).parent / "mem-monitor.log"

# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

SNAPSHOT_RE = re.compile(r"^=== SNAPSHOT\s+(.+)$")
SECTION_RE = re.compile(r"^---\s+(.+?)\s+---$")
# Top-30 line: PID PPID RSS(MB) %MEM CMD...
TOP_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(.+)$")
SWAP_RE = re.compile(r"vm\.swapusage: total = ([\d.]+)M\s+used = ([\d.]+)M\s+free = ([\d.]+)M")
PAGEOUTS_RE = re.compile(r"Pageouts \(cumulative\):\s+(\d+)")
COMPRESSED_RE = re.compile(r"^Compressed\s*:\s+(\d+)\s+MB")
FREE_RE = re.compile(r"^Free\s*:\s+(\d+)\s+MB")
PRESSURE_RE = re.compile(r"Memory pressure:.*?has\s+(\d+)\s+\((\d+)\s+pages")


@dataclass
class ProcSample:
    pid: int
    ppid: int
    rss_mb: float
    pmem: float
    cmd: str


@dataclass
class Snapshot:
    ts: datetime
    procs: list[ProcSample] = field(default_factory=list)
    swap_used_mb: float = 0.0
    swap_total_mb: float = 0.0
    pageouts: int = 0
    compressed_mb: int = 0
    free_mb: int = 0


def parse_log(path: Path) -> list[Snapshot]:
    snapshots: list[Snapshot] = []
    current: Optional[Snapshot] = None
    section: Optional[str] = None
    capturing_top = False

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.rstrip()

        m = SNAPSHOT_RE.match(line)
        if m:
            # Parse "2026-04-21 09:49:55 +0100"
            try:
                ts = datetime.strptime(m.group(1).strip(), "%Y-%m-%d %H:%M:%S %z")
            except ValueError:
                ts = datetime.strptime(
                    m.group(1).strip().rsplit(" ", 1)[0], "%Y-%m-%d %H:%M:%S"
                )
            current = Snapshot(ts=ts)
            snapshots.append(current)
            section = None
            capturing_top = False
            continue

        if current is None:
            continue

        m = SECTION_RE.match(line)
        if m:
            section = m.group(1)
            capturing_top = section.startswith("TOP 30 PROCESSES BY RSS")
            continue

        if capturing_top:
            # Skip header line
            if line.strip().startswith("PID") or not line.strip():
                continue
            m = TOP_RE.match(line)
            if m:
                current.procs.append(
                    ProcSample(
                        pid=int(m.group(1)),
                        ppid=int(m.group(2)),
                        rss_mb=float(m.group(3)),
                        pmem=float(m.group(4)),
                        cmd=m.group(5).strip(),
                    )
                )
            continue

        # System memory fields can appear regardless of which section
        if section and "SYSTEM MEMORY" in section:
            mm = COMPRESSED_RE.match(line)
            if mm:
                current.compressed_mb = int(mm.group(1))
            mm = FREE_RE.match(line)
            if mm:
                current.free_mb = int(mm.group(1))

        mm = SWAP_RE.search(line)
        if mm:
            current.swap_total_mb = float(mm.group(1))
            current.swap_used_mb = float(mm.group(2))

        mm = PAGEOUTS_RE.search(line)
        if mm:
            current.pageouts = int(mm.group(1))

    return snapshots


# ─────────────────────────────────────────────────────────────────────────────
# Classification — figure out WHAT a process is, not just "Code Helper (Plugin)"
# ─────────────────────────────────────────────────────────────────────────────

def classify(cmd: str) -> tuple[str, str]:
    """Return (category, label) where label is specific enough to act on."""
    # tsserver — tag with workspace hash
    m = re.search(r"/vscode-typescript\d+/([a-f0-9]+)/", cmd)
    if "tsserver.js" in cmd and m:
        mode = "semantic" if "serverMode partialSemantic" not in cmd else "partial"
        return ("tsserver", f"tsserver [{mode}] ws={m.group(1)[:12]}")
    if "tsserver.js" in cmd:
        return ("tsserver", "tsserver (unknown workspace)")
    if "typingsInstaller.js" in cmd:
        return ("tsserver", "tsserver typingsInstaller")

    # ESLint
    m = re.search(r"--clientProcessId=(\d+)", cmd)
    if "eslintServer.js" in cmd:
        cp = m.group(1) if m else "?"
        return ("eslint", f"eslintServer (extHost={cp})")

    # GraphQL
    if "vscode-graphql" in cmd and "serverIpc" in cmd:
        cp = m.group(1) if m else "?"
        return ("graphql", f"graphql-language-server (extHost={cp})")

    # JSON / markdown
    if "json-language-features/server" in cmd:
        return ("json-ls", "json-language-server")
    if "markdown-language-features" in cmd:
        return ("markdown-ls", "markdown-language-server")

    # Copilot
    if "github.copilot-chat" in cmd and ".vscode/extensions" in cmd:
        return ("copilot", "copilot-chat extension host")
    if "github.copilot" in cmd:
        return ("copilot", "copilot extension")

    # Other VS Code extensions by path
    m = re.search(r"/\.vscode/extensions/([^/]+)/", cmd)
    if m:
        return ("vscode-ext", f"ext:{m.group(1)}")

    # VS Code roles
    if "Code Helper (Renderer)" in cmd:
        m = re.search(r"--vscode-window-config=vscode:([0-9a-f]+)", cmd)
        wid = m.group(1)[:8] if m else "?"
        return ("vscode-renderer", f"renderer window={wid}")
    if "Code Helper (GPU)" in cmd:
        return ("vscode-gpu", "gpu-process")
    if "utility-sub-type=node.mojom.NodeService" in cmd:
        return ("vscode-extension-host", "extension-host")
    if "Code Helper (Plugin)" in cmd:
        return ("vscode-plugin", "Code Helper (Plugin) generic")
    if "Code Helper" in cmd:
        return ("vscode-helper", "Code Helper generic")
    if re.search(r"/Visual Studio Code\.app/Contents/MacOS/Code$", cmd):
        return ("vscode-main", "VS Code main")

    # Browsers
    if "Google Chrome" in cmd:
        return ("chrome", "Chrome")
    if "Slack.app" in cmd:
        return ("slack", "Slack")
    if "Google Drive" in cmd:
        return ("gdrive", "Google Drive")

    # pi
    if re.match(r"^pi(\s|$)", cmd) or "/pi-monorepo/" in cmd or "pi-coding-agent" in cmd:
        return ("pi", "pi agent")

    # shell / bash / node fallbacks
    if cmd.startswith("/bin/zsh") or cmd.startswith("/bin/bash"):
        return ("shell", "shell")
    if cmd.startswith("node") or " node " in cmd:
        return ("node", "node (unclassified)")

    return ("other", cmd[:80])


# ─────────────────────────────────────────────────────────────────────────────
# Growth analysis
# ─────────────────────────────────────────────────────────────────────────────

def linreg_slope(xs: list[float], ys: list[float]) -> float:
    """Slope in units of y per unit of x (least-squares)."""
    if len(xs) < 2:
        return 0.0
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


@dataclass
class PidSeries:
    pid: int
    cmd: str
    category: str
    label: str
    samples: list[tuple[datetime, float]] = field(default_factory=list)

    @property
    def first_rss(self) -> float:
        return self.samples[0][1] if self.samples else 0.0

    @property
    def last_rss(self) -> float:
        return self.samples[-1][1] if self.samples else 0.0

    @property
    def max_rss(self) -> float:
        return max((s[1] for s in self.samples), default=0.0)

    @property
    def min_rss(self) -> float:
        return min((s[1] for s in self.samples), default=0.0)

    @property
    def duration_hours(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        return (self.samples[-1][0] - self.samples[0][0]).total_seconds() / 3600

    @property
    def growth_mb_per_hour(self) -> float:
        if len(self.samples) < 3:
            return 0.0
        t0 = self.samples[0][0]
        xs = [(s[0] - t0).total_seconds() / 3600 for s in self.samples]
        ys = [s[1] for s in self.samples]
        return linreg_slope(xs, ys)

    @property
    def monotonic_score(self) -> float:
        """Fraction of consecutive samples where RSS grew (0..1)."""
        if len(self.samples) < 2:
            return 0.0
        grew = sum(
            1
            for a, b in zip(self.samples, self.samples[1:])
            if b[1] > a[1]
        )
        return grew / (len(self.samples) - 1)


def build_series(snapshots: list[Snapshot]) -> dict[int, PidSeries]:
    series: dict[int, PidSeries] = {}
    for snap in snapshots:
        for p in snap.procs:
            s = series.get(p.pid)
            if s is None:
                cat, lbl = classify(p.cmd)
                s = PidSeries(pid=p.pid, cmd=p.cmd, category=cat, label=lbl)
                series[p.pid] = s
            s.samples.append((snap.ts, p.rss_mb))
    return series


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def fmt_mb(mb: float) -> str:
    if mb >= 1024:
        return f"{mb/1024:.2f} GB"
    return f"{mb:.0f} MB"


def h1(s: str) -> None:
    print()
    print("═" * 80)
    print(s)
    print("═" * 80)


def h2(s: str) -> None:
    print()
    print("─" * 80)
    print(s)
    print("─" * 80)


def report(snapshots: list[Snapshot], series: dict[int, PidSeries]) -> None:
    if not snapshots:
        print("No snapshots parsed.")
        return

    first = snapshots[0]
    last = snapshots[-1]
    span_h = (last.ts - first.ts).total_seconds() / 3600

    h1("OVERVIEW")
    print(f"Snapshots            : {len(snapshots)}")
    print(f"Time span            : {first.ts}  →  {last.ts}  ({span_h:.1f}h)")
    print(f"Unique PIDs tracked  : {len(series)}")
    print(
        f"Snapshots with swap  : "
        f"first={first.swap_used_mb:.0f} MB  last={last.swap_used_mb:.0f} MB  "
        f"max={max(s.swap_used_mb for s in snapshots):.0f} MB"
    )
    pageout_delta = last.pageouts - first.pageouts
    print(
        f"Pageouts (cumulative): first={first.pageouts:,}  last={last.pageouts:,}  "
        f"Δ={pageout_delta:,}"
    )
    print(
        f"Compressed RAM       : first={first.compressed_mb:,} MB  "
        f"last={last.compressed_mb:,} MB  "
        f"Δ={last.compressed_mb - first.compressed_mb:+,} MB"
    )
    print(
        f"Free RAM             : first={first.free_mb:,} MB  last={last.free_mb:,} MB"
    )

    # ─── Swap / compression trend over time ────────────────────────────────
    h1("SYSTEM-WIDE MEMORY PRESSURE TIMELINE")
    print(f"{'time':<20}{'free':>10}{'compressed':>14}{'swap_used':>12}{'pageouts':>14}")
    step = max(1, len(snapshots) // 20)
    for i, s in enumerate(snapshots):
        if i % step == 0 or i == len(snapshots) - 1:
            print(
                f"{s.ts.strftime('%Y-%m-%d %H:%M'):<20}"
                f"{s.free_mb:>10,}"
                f"{s.compressed_mb:>14,}"
                f"{s.swap_used_mb:>12.0f}"
                f"{s.pageouts:>14,}"
            )

    # ─── Top growers (by absolute MB gained) ───────────────────────────────
    # Only processes seen in ≥3 snapshots that gained meaningful RSS.
    long_lived = [
        s for s in series.values() if len(s.samples) >= 3 and s.duration_hours >= 0.5
    ]
    growers = sorted(
        long_lived,
        key=lambda s: (s.last_rss - s.first_rss),
        reverse=True,
    )

    h1(f"TOP 25 ABSOLUTE GROWERS (Δ RSS across lifespan ≥ 0.5h)")
    print(
        f"{'PID':<7}{'first':>9}{'last':>9}{'max':>9}{'Δ':>9}"
        f"{'MB/hr':>9}{'mono%':>7}{'span h':>8}  category / label"
    )
    for s in growers[:25]:
        delta = s.last_rss - s.first_rss
        if delta < 20:  # noise threshold
            break
        print(
            f"{s.pid:<7}"
            f"{s.first_rss:>9.0f}"
            f"{s.last_rss:>9.0f}"
            f"{s.max_rss:>9.0f}"
            f"{delta:>+9.0f}"
            f"{s.growth_mb_per_hour:>9.1f}"
            f"{s.monotonic_score*100:>6.0f}%"
            f"{s.duration_hours:>8.1f}  "
            f"{s.category:<20} {s.label}"
        )

    # ─── Top growers by rate (MB/hr) ───────────────────────────────────────
    by_rate = sorted(
        [s for s in long_lived if s.duration_hours >= 1.0 and s.growth_mb_per_hour > 5],
        key=lambda s: s.growth_mb_per_hour,
        reverse=True,
    )
    h1("TOP 25 RATE-BASED LEAKERS (MB/hour, linear regression)")
    print(
        f"{'PID':<7}{'first':>9}{'last':>9}{'MB/hr':>9}{'mono%':>7}"
        f"{'span h':>8}  category / label"
    )
    for s in by_rate[:25]:
        print(
            f"{s.pid:<7}"
            f"{s.first_rss:>9.0f}"
            f"{s.last_rss:>9.0f}"
            f"{s.growth_mb_per_hour:>9.2f}"
            f"{s.monotonic_score*100:>6.0f}%"
            f"{s.duration_hours:>8.1f}  "
            f"{s.category:<20} {s.label}"
        )

    # ─── Aggregate by category ────────────────────────────────────────────
    h1("GROWTH BY CATEGORY (sums across all PIDs in category)")
    cat_data: dict[str, dict] = defaultdict(
        lambda: {"delta": 0.0, "final": 0.0, "first": 0.0, "count": 0, "pids": []}
    )
    for s in long_lived:
        d = cat_data[s.category]
        d["delta"] += s.last_rss - s.first_rss
        d["final"] += s.last_rss
        d["first"] += s.first_rss
        d["count"] += 1
        d["pids"].append(s.pid)

    rows = sorted(cat_data.items(), key=lambda kv: kv[1]["delta"], reverse=True)
    print(
        f"{'category':<24}{'N':>4}{'first':>12}{'final':>12}{'Δ':>12}{'avg Δ/proc':>12}"
    )
    for cat, d in rows:
        if d["count"] == 0:
            continue
        avg = d["delta"] / d["count"]
        print(
            f"{cat:<24}{d['count']:>4}"
            f"{fmt_mb(d['first']):>12}"
            f"{fmt_mb(d['final']):>12}"
            f"{d['delta']:>+11.0f}M"
            f"{avg:>+11.0f}M"
        )

    # ─── Deep-dive: the #1 suspect ────────────────────────────────────────
    if growers:
        top = growers[0]
        h1(f"DEEP DIVE #1 SUSPECT — PID {top.pid}  {top.label}")
        print(f"Category           : {top.category}")
        print(f"First seen         : {top.samples[0][0]}  @ {top.first_rss:.0f} MB")
        print(f"Last seen          : {top.samples[-1][0]}  @ {top.last_rss:.0f} MB")
        print(f"Peak               : {top.max_rss:.0f} MB")
        print(f"Growth             : {top.last_rss - top.first_rss:+.0f} MB over {top.duration_hours:.1f}h  ({top.growth_mb_per_hour:+.1f} MB/hr)")
        print(f"Monotonic fraction : {top.monotonic_score*100:.0f}%")
        print()
        print("RSS trajectory (every ~hour):")
        step = max(1, len(top.samples) // 24)
        for i, (t, rss) in enumerate(top.samples):
            if i % step == 0 or i == len(top.samples) - 1:
                bar = "▇" * int(rss / 50)
                print(f"  {t.strftime('%m-%d %H:%M'):<14}{rss:>7.0f} MB  {bar}")
        print()
        print("Full cmdline:")
        # Wrap long cmdlines
        cmd = top.cmd
        for i in range(0, len(cmd), 100):
            print(f"  {cmd[i:i+100]}")

    # ─── Group by cmdline signature (identical scripts across PIDs) ───────
    h2("GROWERS GROUPED BY NORMALIZED CMDLINE SIGNATURE")
    # Normalize: strip numeric IDs, tmp paths, window configs
    def sig(cmd: str) -> str:
        s = re.sub(r"/\d+[a-f0-9]{6,}/", "/<HASH>/", cmd)
        s = re.sub(r"tscancellation-[a-f0-9]+\.tmp\*?", "tscancellation-<ID>", s)
        s = re.sub(r"--clientProcessId=\d+", "--clientProcessId=<N>", s)
        s = re.sub(r"--renderer-client-id=\d+", "--renderer-client-id=<N>", s)
        s = re.sub(r"--vscode-window-config=vscode:[0-9a-f-]+", "--vscode-window-config=<W>", s)
        s = re.sub(r"--time-ticks-at-unix-epoch=-?\d+", "--time-ticks=<T>", s)
        s = re.sub(r"--launch-time-ticks=\d+", "--launch-ticks=<T>", s)
        s = re.sub(r"--trace-process-track-uuid=\d+", "--track-uuid=<U>", s)
        s = re.sub(r"--seatbelt-client=\d+", "--seatbelt-client=<N>", s)
        s = re.sub(r"--cancellationPipeName\s+\S+", "--cancellationPipeName <P>", s)
        return s[:200]

    sig_groups: dict[str, list[PidSeries]] = defaultdict(list)
    for s in long_lived:
        if s.last_rss - s.first_rss > 50:
            sig_groups[sig(s.cmd)].append(s)

    grouped = sorted(
        sig_groups.items(),
        key=lambda kv: sum(x.last_rss - x.first_rss for x in kv[1]),
        reverse=True,
    )
    for sg, procs in grouped[:10]:
        total = sum(p.last_rss - p.first_rss for p in procs)
        print()
        print(f"Δ total: {total:+.0f} MB across {len(procs)} PID(s)")
        print(f"  PIDs: {', '.join(str(p.pid) for p in procs)}")
        print(f"  category: {procs[0].category}  /  {procs[0].label}")
        print(f"  signature: {sg[:160]}")

    # ─── Actionable recommendations ───────────────────────────────────────
    h1("ACTIONABLE RECOMMENDATIONS")
    recs: list[str] = []

    # check each category's contribution
    def cat_stats(name: str):
        d = cat_data.get(name)
        return d["delta"] if d else 0

    pi_delta = cat_stats("pi")
    tsserver_delta = cat_stats("tsserver")
    eslint_delta = cat_stats("eslint")
    graphql_delta = cat_stats("graphql")
    exthost_delta = cat_stats("vscode-extension-host")
    renderer_delta = cat_stats("vscode-renderer")
    copilot_delta = cat_stats("copilot")

    # Rank contributors
    totals = [
        ("pi agent", pi_delta),
        ("tsserver (TypeScript)", tsserver_delta),
        ("eslintServer", eslint_delta),
        ("graphql language server", graphql_delta),
        ("VS Code extension hosts", exthost_delta),
        ("VS Code renderers", renderer_delta),
        ("GitHub Copilot", copilot_delta),
    ]
    totals.sort(key=lambda kv: kv[1], reverse=True)
    print("\nWho grew the most, in order:")
    for name, d in totals:
        if d > 0:
            print(f"  • {name}: +{d:.0f} MB")

    # pi agent specifically
    pi_procs = [s for s in long_lived if s.category == "pi"]
    if pi_procs:
        pi_top = max(pi_procs, key=lambda s: s.last_rss - s.first_rss)
        if pi_top.last_rss - pi_top.first_rss > 200:
            recs.append(
                f"🔴 pi agent (PID {pi_top.pid}) leaked {pi_top.last_rss - pi_top.first_rss:+.0f} MB "
                f"({pi_top.growth_mb_per_hour:+.1f} MB/hr). "
                f"Capture a heap snapshot (threshold already set to 1500 MB; drop it lower). "
                f"Check ~/.pi/extensions/ and ~/.pi/agent/extensions/ for the culprit."
            )
        elif pi_top.last_rss - pi_top.first_rss > 50:
            recs.append(
                f"🟡 pi agent (PID {pi_top.pid}) grew {pi_top.last_rss - pi_top.first_rss:+.0f} MB "
                f"— modest but noticeable. Watch longer to confirm."
            )

    # tsserver — expected to cache, look for outliers
    ts_procs = [s for s in long_lived if s.category == "tsserver"]
    ts_outliers = [s for s in ts_procs if s.last_rss > 2000 or s.growth_mb_per_hour > 30]
    if ts_outliers:
        for s in ts_outliers[:3]:
            recs.append(
                f"🔴 tsserver PID {s.pid} is {s.last_rss:.0f} MB "
                f"(growth {s.growth_mb_per_hour:+.1f} MB/hr). "
                f"Workspace: {s.label}. "
                f"Consider closing that VS Code window or running `TypeScript: Restart TS Server` in it."
            )

    # eslintServer — frequently leaks
    el_procs = [s for s in long_lived if s.category == "eslint"]
    el_bad = [s for s in el_procs if s.last_rss - s.first_rss > 200 or s.last_rss > 500]
    if el_bad:
        for s in el_bad[:3]:
            recs.append(
                f"🔴 ESLint server PID {s.pid} hit {s.last_rss:.0f} MB "
                f"(Δ{s.last_rss - s.first_rss:+.0f} MB over {s.duration_hours:.1f}h). "
                f"This is a known ESLint memory-leak pattern. "
                f"Fix: disable `dbaeumer.vscode-eslint` in the affected workspace, "
                f"or set `eslint.runtime` to a higher max-old-space-size, "
                f"or add `.eslintignore` entries to reduce scanned files."
            )

    # graphql
    gq_bad = [
        s for s in long_lived
        if s.category == "graphql" and (s.last_rss > 300 or s.growth_mb_per_hour > 10)
    ]
    if gq_bad:
        for s in gq_bad[:2]:
            recs.append(
                f"🟡 graphql-language-server PID {s.pid} at {s.last_rss:.0f} MB. "
                f"Consider disabling `graphql.vscode-graphql` if not in active use."
            )

    # copilot
    cp_procs = [s for s in long_lived if s.category == "copilot"]
    cp_bad = [s for s in cp_procs if s.last_rss - s.first_rss > 150]
    if cp_bad:
        for s in cp_bad[:2]:
            recs.append(
                f"🟡 Copilot PID {s.pid} grew {s.last_rss - s.first_rss:+.0f} MB. "
                f"If conversations are long, 'Clear Chat History' or reload window."
            )

    # Extension hosts — but only if the growth isn't already explained by children
    eh_bad = [s for s in long_lived if s.category == "vscode-extension-host" and s.last_rss - s.first_rss > 300]
    if eh_bad:
        for s in eh_bad[:3]:
            recs.append(
                f"🟠 Extension host PID {s.pid} grew {s.last_rss - s.first_rss:+.0f} MB. "
                f"Run `Developer: Show Running Extensions` in VS Code to see which extension in that host is responsible."
            )

    # swap/pageout escalation
    if pageout_delta > 100_000:
        recs.append(
            f"🔴 Pageouts grew by {pageout_delta:,} over the window — macOS is compressing/swapping heavily. "
            f"Matches the symptom you described. The processes above are the cause."
        )

    # heap snapshot guidance
    if pi_procs:
        pi_top = max(pi_procs, key=lambda s: s.last_rss)
        if pi_top.last_rss > 500:
            recs.append(
                f"💡 Next leak round: run `PI_HEAP_THRESHOLD_MB={int(pi_top.last_rss * 0.7)} ./mem-monitor.sh` "
                f"so the trigger fires before the leak peaks. "
                f"Use Chrome DevTools → chrome://inspect → localhost:9229 → take heap snapshot → sort by Retained Size."
            )

    if not recs:
        print("\nNo leaks exceeding thresholds were detected in this log window.")
    else:
        for r in recs:
            print(f"\n  {r}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else LOG_DEFAULT
    if not path.exists():
        print(f"Log not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {path}…")
    snapshots = parse_log(path)
    if not snapshots:
        print("No snapshots found in log.")
        sys.exit(1)
    print(f"Parsed {len(snapshots)} snapshots.")
    series = build_series(snapshots)
    print(f"Tracked {len(series)} unique PIDs.")
    report(snapshots, series)


if __name__ == "__main__":
    main()
