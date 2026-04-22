# AGENTS.md

Guidance for AI agents handed this repo. See [README.md](./README.md) for tool
overview, setup, and usage.

## Analyzing an existing log

1. Run `python3 analyze-leaks.py` first. It surfaces everything actionable.
2. Only drill into `mem-monitor.log` manually if the analyzer's top suspects
   don't match the user's intuition — e.g. if they suspect pi but the
   analyzer shows tsserver, mention both and invite them to choose.
3. The analyzer filters growth rates above noise. Don't report small
   (+20-50 MB) drifts as leaks — the recommendations section already
   excludes them.
4. If `heap-snapshots/` has artefacts, read the generated `.README.md`
   inside to explain next steps for JS-heap-snapshot capture. Don't
   re-derive those instructions.
