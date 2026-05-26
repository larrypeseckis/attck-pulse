# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.16.0
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# %% [markdown]
# # attck-pulse: dataset overview and findings
#
# This notebook produces the analytical output for two LinkedIn posts in the
# attck-pulse series:
#
# - **Post 2**: Cross-source ATT&CK technique attestation across CISA Joint
#   Cybersecurity Advisories and The DFIR Report public intrusion writeups
# - **Post 3**: Technique/tactic frequency and per-report yield distribution
#
# All figures are saved to `notebooks/figures/` as PNG for LinkedIn upload.
#
# **Run order**: top to bottom. Each section is independent so you can re-run
# one section without recomputing the others.
#
# **Honest current scope**: n=20 reports (10 CISA AA + 10 DFIR), 14 of them
# mention-bearing, producing 507 technique mentions across 14 tactics. The
# 6 zero-yield reports are themselves a finding — see Section 4. Treat
# magnitudes as directional, not authoritative.

# %% [markdown]
# ## Section 0: setup

# %%
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sqlalchemy import text

# Make src importable without installing the package
PROJECT_ROOT = Path.cwd().resolve()
if PROJECT_ROOT.name == "notebooks":
    PROJECT_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_intel.db import get_engine  # noqa: E402

ENGINE = get_engine()

# Figure output directory
FIGURES_DIR = PROJECT_ROOT / "notebooks" / "figures"
FIGURES_DIR.mkdir(exist_ok=True, parents=True)

# Plot styling
sns.set_theme(style="whitegrid", context="talk")
plt.rcParams["figure.dpi"] = 100
plt.rcParams["savefig.dpi"] = 150
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["font.family"] = "sans-serif"

# Color palette - colorblind-safe, distinct between sources
PALETTE_CISA = "#1f77b4"   # blue
PALETTE_DFIR = "#d62728"   # red
PALETTE_BOTH = "#2ca02c"   # green for cross-source

print(f"Project root: {PROJECT_ROOT}")
print(f"Figures will be saved to: {FIGURES_DIR}")


# %%
def run_query(sql: str, params: dict | None = None) -> pd.DataFrame:
    """Run a SQL query and return a DataFrame.

    Wraps SQLAlchemy with sensible defaults for this notebook's queries.
    """
    with ENGINE.connect() as conn:
        return pd.read_sql_query(text(sql), conn, params=params or {})


# %% [markdown]
# ## Section 1: dataset summary
#
# Confirms the dataset size and shape before any analytical claims.
# This section's table is referenced in both Post 2 and Post 3 as the
# "honest small-n" framing.

# %%
DATASET_SUMMARY_SQL = """
SELECT
    r.report_type,
    COUNT(DISTINCT r.id) AS reports,
    COUNT(DISTINCT r.id) FILTER (WHERE r.id IN (
        SELECT report_id FROM technique_mentions
    )) AS reports_with_mentions,
    COALESCE((
        SELECT COUNT(*)
        FROM technique_mentions tm
        JOIN reports r2 ON r2.id = tm.report_id
        WHERE r2.report_type = r.report_type
    ), 0) AS mentions,
    COALESCE((
        SELECT COUNT(DISTINCT technique_id)
        FROM technique_mentions tm
        JOIN reports r2 ON r2.id = tm.report_id
        WHERE r2.report_type = r.report_type
    ), 0) AS unique_techniques
FROM reports r
GROUP BY r.report_type
ORDER BY r.report_type;
"""

dataset_summary = run_query(DATASET_SUMMARY_SQL)
dataset_summary

# %% [markdown]
# ## Section 2: cross-source attestation (Post 2)
#
# **The analytical question**: which ATT&CK techniques are cited across both
# CISA-curated Joint Cybersecurity Advisories and DFIR Report independent
# intrusion writeups? Cross-source attestation is a stronger signal than
# single-source attestation because the techniques are independently confirmed.
#
# **Expected finding to lead with**: T1016 (System Network Configuration
# Discovery) is the highest cross-source-attested technique outside of the
# expected consensus picks (T1059.001 PowerShell, T1021.001 RDP). Discovery
# techniques rank higher than initial-access techniques across the corpus,
# which inverts a common defender prior that prioritizes initial-access
# detection.

# %%
CROSS_SOURCE_SQL = """
WITH per_source AS (
    SELECT
        tm.technique_id,
        CASE
            WHEN r.report_type = 'cisa_advisory_aa' THEN 'cisa'
            WHEN r.report_type LIKE 'dfir_%' THEN 'dfir'
        END AS source_group,
        COUNT(DISTINCT tm.report_id) AS reports_citing
    FROM technique_mentions tm
    JOIN reports r ON r.id = tm.report_id
    WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
    GROUP BY tm.technique_id, source_group
),
aggregated AS (
    SELECT
        technique_id,
        COUNT(DISTINCT source_group) AS distinct_source_groups,
        COALESCE(SUM(reports_citing) FILTER (WHERE source_group = 'cisa'), 0) AS cisa_reports,
        COALESCE(SUM(reports_citing) FILTER (WHERE source_group = 'dfir'), 0) AS dfir_reports,
        COALESCE(SUM(reports_citing), 0) AS total_reports
    FROM per_source
    GROUP BY technique_id
)
SELECT
    a.technique_id,
    t.name AS technique_name,
    t.tactic,
    a.cisa_reports,
    a.dfir_reports,
    a.total_reports
FROM aggregated a
JOIN techniques t ON t.technique_id = a.technique_id
WHERE a.distinct_source_groups >= 2
ORDER BY a.total_reports DESC, a.cisa_reports DESC
LIMIT 25;
"""

cross_source = run_query(CROSS_SOURCE_SQL)
print(f"Techniques attested in both CISA and DFIR: {len(cross_source)}")
cross_source

# %% [markdown]
# ### Chart: top 15 cross-source-attested techniques
#
# Horizontal grouped bar chart. CISA bar + DFIR bar per technique. The visual
# story: which techniques have *both* bars sized substantially. T1016 should
# be visually prominent if the prediction holds.

# %%
top_n = 15
chart_data = cross_source.head(top_n).copy()
chart_data["label"] = chart_data["technique_id"] + ": " + chart_data["technique_name"]

# Sort ascending for horizontal bar (top item appears at top of chart)
chart_data = chart_data.iloc[::-1].reset_index(drop=True)

fig, ax = plt.subplots(figsize=(11, 9))

y_positions = range(len(chart_data))
bar_height = 0.4

ax.barh(
    [y + bar_height / 2 for y in y_positions],
    chart_data["cisa_reports"],
    height=bar_height,
    color=PALETTE_CISA,
    label="CISA AA advisories",
)
ax.barh(
    [y - bar_height / 2 for y in y_positions],
    chart_data["dfir_reports"],
    height=bar_height,
    color=PALETTE_DFIR,
    label="DFIR Report writeups",
)

ax.set_yticks(list(y_positions))
ax.set_yticklabels(chart_data["label"], fontsize=10)
ax.set_xlabel("Reports citing the technique")
ax.set_title(
    f"Top {top_n} ATT&CK techniques cited across both CISA AA advisories\n"
    f"and DFIR Report intrusion writeups (n=20 reports)",
    fontsize=13,
    loc="left",
)
ax.legend(loc="lower right", framealpha=0.95)
ax.grid(axis="y", visible=False)

plt.tight_layout()
fig.savefig(FIGURES_DIR / "post2_cross_source_top15.png")
plt.show()
print(f"Saved: {FIGURES_DIR / 'post2_cross_source_top15.png'}")

# %% [markdown]
# ### Per-tactic breakdown of cross-source-attested techniques
#
# Supports the secondary finding: discovery tactics dominate the
# cross-source-attested set, ahead of initial access. This view answers
# "*what kind of behavior* is consistently mapped to ATT&CK by both
# editorial cultures?"

# %%
cross_source_by_tactic = (
    cross_source.groupby("tactic")
    .agg(techniques=("technique_id", "count"), total_reports=("total_reports", "sum"))
    .sort_values("total_reports", ascending=False)
    .reset_index()
)
cross_source_by_tactic

# %% [markdown]
# ## Section 3: tactic distribution (Post 3)
#
# **The analytical question**: across all 507 technique mentions, how do the
# 14 ATT&CK tactics distribute? Which tactical phases of the kill chain are
# best-represented in current threat intel reporting?
#
# **Finding** (verified against the live dataset, 2026-05-18): Discovery leads
# (81 mentions), then Defense Evasion (70), Credential Access (56), Execution
# (54), and Command and Control (50). Discovery topping the distribution
# reinforces the Section 2 cross-source result — recon behavior is both the
# most-attested *and* the most-frequent category. Impact ranks low, which is
# what separates this APT-flavored corpus from a ransomware-dominant one.

# %%
TACTIC_DISTRIBUTION_SQL = """
SELECT
    t.tactic,
    COUNT(*) AS mentions,
    COUNT(DISTINCT tm.technique_id) AS unique_techniques,
    COUNT(DISTINCT tm.report_id) AS reports
FROM technique_mentions tm
JOIN techniques t ON t.technique_id = tm.technique_id
JOIN reports r ON r.id = tm.report_id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
  AND t.tactic IS NOT NULL
GROUP BY t.tactic
ORDER BY mentions DESC;
"""

tactic_dist = run_query(TACTIC_DISTRIBUTION_SQL)
tactic_dist

# %% [markdown]
# ### Chart: tactic distribution across all mentions

# %%
fig, ax = plt.subplots(figsize=(11, 7))

bars = ax.barh(
    tactic_dist["tactic"].iloc[::-1],
    tactic_dist["mentions"].iloc[::-1],
    color=PALETTE_CISA,
)

# Annotate each bar with the count
for bar, value in zip(bars, tactic_dist["mentions"].iloc[::-1], strict=False):
    ax.text(
        bar.get_width() + max(tactic_dist["mentions"]) * 0.01,
        bar.get_y() + bar.get_height() / 2,
        str(int(value)),
        va="center",
        fontsize=10,
    )

ax.set_xlabel("Mentions")
ax.set_title(
    f"ATT&CK tactic distribution across {tactic_dist['mentions'].sum()} mentions\n"
    f"(CISA AA advisories + DFIR Report writeups, n=20 reports)",
    fontsize=13,
    loc="left",
)
ax.grid(axis="y", visible=False)

plt.tight_layout()
fig.savefig(FIGURES_DIR / "post3_tactic_distribution.png")
plt.show()
print(f"Saved: {FIGURES_DIR / 'post3_tactic_distribution.png'}")

# %% [markdown]
# ## Section 4: per-report yield and the bimodal DFIR distribution (Post 3)
#
# **The analytical question**: how many technique mentions does a typical
# report produce? Are the sources uniformly productive or concentrated?
#
# **Expected finding**: bimodal for DFIR (5 reports producing 19-43 mentions,
# 5 reports producing zero because their ATT&CK section is JavaScript-rendered
# and the v1 static-fetch ingester can't reach it). CISA AA is also uneven
# but not bimodal — a power-law-ish distribution where 4 advisories produce
# ~80% of mentions.

# %%
PER_REPORT_YIELD_SQL = """
SELECT
    r.id,
    LEFT(r.title, 60) AS title,
    r.report_type,
    COALESCE(COUNT(tm.id), 0) AS mentions
FROM reports r
LEFT JOIN technique_mentions tm ON tm.report_id = r.id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
GROUP BY r.id, r.title, r.report_type
ORDER BY r.report_type, mentions DESC;
"""

per_report = run_query(PER_REPORT_YIELD_SQL)
print(f"Reports analyzed: {len(per_report)}")
print(f"Reports with zero mentions: {(per_report['mentions'] == 0).sum()}")
per_report

# %% [markdown]
# ### Chart: per-report mention yield by source
#
# Strip plot, one dot per report, x-axis = mention count, y-axis = source.
# The bimodal DFIR pattern (cluster at 0 + cluster at 20-45) should be
# immediately visible. CISA AA's power-law tail visible as the spread.

# %%
# Normalize source labels
per_report_chart = per_report.copy()
per_report_chart["source_label"] = per_report_chart["report_type"].map(
    {
        "cisa_advisory_aa": "CISA Joint Advisories",
        "dfir_full_report": "DFIR Report (full)",
        "dfir_flash_alert": "DFIR Report (flash)",
    }
)

fig, ax = plt.subplots(figsize=(11, 5))

sns.stripplot(
    data=per_report_chart,
    x="mentions",
    y="source_label",
    hue="source_label",
    size=14,
    jitter=0.15,
    alpha=0.75,
    legend=False,
    palette={
        "CISA Joint Advisories": PALETTE_CISA,
        "DFIR Report (full)": PALETTE_DFIR,
        "DFIR Report (flash)": PALETTE_DFIR,
    },
    ax=ax,
)

ax.set_xlabel("Technique mentions per report")
ax.set_ylabel("")
ax.set_title(
    "Per-report mention yield by source\n"
    "DFIR cluster at zero is the JS-rendering gap (a property, not a bug)",
    fontsize=13,
    loc="left",
)
ax.grid(axis="y", visible=False)

plt.tight_layout()
fig.savefig(FIGURES_DIR / "post3_per_report_yield.png")
plt.show()
print(f"Saved: {FIGURES_DIR / 'post3_per_report_yield.png'}")

# %% [markdown]
# ### Numerical summary of the bimodal DFIR distribution
#
# Quick descriptive stats to back the visual claim.

# %%
yield_summary = (
    per_report_chart.groupby("source_label")
    .agg(
        reports=("id", "count"),
        zero_yield=("mentions", lambda s: (s == 0).sum()),
        nonzero_yield=("mentions", lambda s: (s > 0).sum()),
        min_nonzero=("mentions", lambda s: s[s > 0].min() if (s > 0).any() else None),
        max_yield=("mentions", "max"),
        mean_nonzero=("mentions", lambda s: s[s > 0].mean() if (s > 0).any() else None),
    )
    .reset_index()
)
yield_summary

# %% [markdown]
# ## Section 5: optional extras
#
# These cells produce additional context that may or may not make it into the
# posts. Run them if you have time on May 27. Skip them if you don't — none are
# load-bearing for posts 2 or 3.

# %% [markdown]
# ### Extraction method comparison (validates Post 1's methodology claims)

# %%
METHOD_COMPARISON_SQL = """
SELECT
    r.report_type,
    tm.extraction_method,
    COUNT(*) AS mentions,
    COUNT(DISTINCT tm.technique_id) AS unique_techniques
FROM technique_mentions tm
JOIN reports r ON r.id = tm.report_id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
GROUP BY r.report_type, tm.extraction_method
ORDER BY r.report_type, tm.extraction_method;
"""

method_comparison = run_query(METHOD_COMPARISON_SQL)
method_comparison

# %% [markdown]
# ### Techniques unique to one source (the gaps cross-source attestation misses)

# %%
UNIQUE_TO_SOURCE_SQL = """
WITH per_source AS (
    SELECT
        tm.technique_id,
        CASE
            WHEN r.report_type = 'cisa_advisory_aa' THEN 'cisa'
            WHEN r.report_type LIKE 'dfir_%' THEN 'dfir'
        END AS source_group,
        COUNT(DISTINCT tm.report_id) AS reports_citing
    FROM technique_mentions tm
    JOIN reports r ON r.id = tm.report_id
    WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
    GROUP BY tm.technique_id, source_group
),
classified AS (
    SELECT
        technique_id,
        COUNT(DISTINCT source_group) AS distinct_source_groups,
        STRING_AGG(source_group, ',' ORDER BY source_group) AS sources,
        SUM(reports_citing) AS total_reports
    FROM per_source
    GROUP BY technique_id
)
SELECT
    c.sources AS appears_in,
    COUNT(*) AS technique_count,
    SUM(c.total_reports) AS total_report_mentions
FROM classified c
GROUP BY c.sources
ORDER BY technique_count DESC;
"""

unique_to_source = run_query(UNIQUE_TO_SOURCE_SQL)
unique_to_source

# %% [markdown]
# ## Section 6: what produced what
#
# Cross-reference of charts saved and which post they support, for the
# May 27 workflow.

# %%
print("Figures saved to:", FIGURES_DIR)
for png in sorted(FIGURES_DIR.glob("*.png")):
    size_kb = png.stat().st_size / 1024
    print(f"  {png.name}  ({size_kb:.1f} KB)")

print()
print("Chart-to-post mapping:")
print("  post2_cross_source_top15.png       -> Post 2 (cross-source attestation)")
print("  post3_tactic_distribution.png      -> Post 3 (frequency)")
print("  post3_per_report_yield.png         -> Post 3 (bimodal DFIR finding)")

# %%
