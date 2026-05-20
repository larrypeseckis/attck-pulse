# attck-pulse notebooks

Analytical notebooks for the attck-pulse dataset.

## Files

- `01_attck_pulse_overview.py` — jupytext py:percent format. Produces all
  charts for LinkedIn posts 2 and 3.
- `figures/` — Output directory. PNGs land here, gitignored.

## How to run

Two equivalent ways. Pick whichever fits the moment.

### Option A: VS Code (recommended)

VS Code's Jupyter extension reads `# %%` cell markers natively. No conversion
step.

1. SSH into the AWS instance with VS Code Remote-SSH
2. Open `notebooks/01_attck_pulse_overview.py`
3. Hit `Run All` in the notebook toolbar, or run cell-by-cell with `Shift+Enter`

### Option B: Classic Jupyter

If you prefer the classic notebook UI, convert once:

```bash
uv pip install -e ".[dev]"   # installs jupytext + jupyterlab into the venv
jupytext --to ipynb notebooks/01_attck_pulse_overview.py
jupyter lab notebooks/01_attck_pulse_overview.ipynb
```

The `.ipynb` is gitignored; the `.py` is the source of truth.

## Dependencies

Beyond the base attck-pulse dependencies, the notebook needs:

- `pandas>=2.2`
- `matplotlib>=3.9`
- `seaborn>=0.13`
- `jupyterlab>=4.2` (only for Option B)
- `jupytext>=1.16` (only for Option B)
- `ipykernel>=6.29` (auto-installed in VS Code)

All of these are already in `pyproject.toml`'s `[dev]` extra, so
`uv pip install -e ".[dev]"` covers them.

## What the notebook produces

| File | Used by | Description |
| --- | --- | --- |
| `figures/post2_cross_source_top15.png` | Post 2 | Top 15 cross-source-attested techniques, grouped horizontal bars |
| `figures/post3_tactic_distribution.png` | Post 3 | 14-tactic distribution bar chart |
| `figures/post3_per_report_yield.png` | Post 3 | Per-report mention yield strip plot showing the bimodal DFIR cluster |

## Chart styling notes

- Seaborn `whitegrid` theme with `talk` context for readable LinkedIn-sized output
- 150 DPI on save (`savefig.dpi = 150`), `bbox_inches='tight'`
- Colorblind-safe palette (Matplotlib defaults), distinct between sources:
  blue for CISA, red for DFIR, green for cross-source
- All titles include explicit n labels for honest small-n framing
- All charts annotate exact values where it adds clarity

## May 27 workflow (post-SSCP)

1. `git pull origin main` on AWS to make sure you have the latest dataset
2. Re-run any ingesters if needed (`python scripts/run_ingester.py cisa_advisories`,
   `python scripts/run_ingester.py dfir_report`) — usually unnecessary, the
   dataset is the dataset
3. Open the notebook (Option A or B above)
4. Run all cells. Should complete in under 30 seconds.
5. PNGs land in `notebooks/figures/`. Open them, eyeball them, screenshot
   from the notebook output if you prefer those over the saved files.
6. Draft post 2. Chart is `post2_cross_source_top15.png`. Hook is T1016
   leading the discovery-tactic cluster.
7. Draft post 3 the following week. Charts are
   `post3_tactic_distribution.png` and `post3_per_report_yield.png`.
   Two data points support two distinct paragraphs: tactic concentration
   and the bimodal DFIR finding.

## Honest scope reminder

n=20 reports across two sources (14 mention-bearing, 6 zero-yield),
507 mentions, 14 tactics. Treat magnitudes as directional, not
authoritative. The method labels and validation numbers are explicit in
METHODOLOGY.md so the dataset doesn't hide what it is.
