# Methodology

This document describes how technique mentions are extracted from threat intel reports, how extraction quality is measured, and what the known limitations are.

## Extraction approach

Two-stage extraction:

### Stage 1: Regex (high precision, partial recall)

ATT&CK technique IDs follow a strict pattern: `T\d{4}(\.\d{3})?` (e.g. `T1059`, `T1059.001`).

A regex pass against report text catches every explicit ID mention. Each match is validated against the loaded `techniques` table — if the ID doesn't exist as a real technique, the match is discarded.

**Stored as:** `extraction_method = 'regex'`, `confidence = 1.0`.

### Stage 2: spaCy NER + keyword matching (lower precision, higher recall)

Many reports describe techniques without using the T-number. "The actor used PowerShell for execution" mentions T1059.001 implicitly.

Approach:
1. Run spaCy NER over the report text
2. For each technique, build a list of canonical name + known aliases
3. Find phrase matches in the text using spaCy's `PhraseMatcher`
4. Score confidence based on co-occurrence with other security-context terms in a ±50-word window

**Stored as:** `extraction_method = 'spacy_phrase'`, `confidence` in `[0.0, 1.0]`.

A configurable threshold (default 0.6) determines which spaCy mentions are included in headline analyses.

## Validation

Extraction quality is validated empirically, not assumed.

### Sampling protocol

After each significant ingest batch:

1. Sample 50 random `technique_mentions` rows stratified by `extraction_method`
2. Manually review each: is this a real mention of this technique in this context?
3. Calculate precision (true positives / total samples) per method
4. Sample 25 random reports, manually identify all technique mentions, compare against pipeline output to estimate recall

### Targets

- Regex precision: ≥95% (failure mode = ID exists but context isn't really discussing the technique)
- spaCy phrase precision: ≥70% at default threshold
- Combined recall: ≥60% (compared against manual analyst review)

If targets aren't met, the pipeline gets fixes before scaling.

Validation results are tracked in `validation_log.md` (not yet created — populated after first run).

## Known limitations

**English only.** Reports in other languages are not processed. Several major sources (Russian, Chinese vendor blogs) are not covered.

**Surface-level extraction.** A report saying "the actor did NOT use T1059" still gets a T1059 mention recorded. Negation handling is not implemented in v1.

**No deduplication across sources.** If three sources report the same incident citing the same techniques, that's three mentions, not one. This is intentional — frequency across independent reporting *is* a signal — but it must be remembered when interpreting trends.

**Reporting bias.** What gets written about reflects vendor priorities, recent victims, and what's commercially interesting. This dataset measures *what threat intel publishers report on*, which is correlated with but not identical to *what attackers actually do*.

**Time-of-publication, not time-of-attack.** Reports often describe activity from months prior. Trend analysis is anchored to publication date, not incident date. Users should interpret trends accordingly.

**ATT&CK version pinning.** The pipeline pins to a specific ATT&CK version. When ATT&CK itself adds or revises techniques, those changes are not reflected until the pin is bumped intentionally. This is a tradeoff favoring reproducibility over freshness.

## Source-specific extraction yields

Not all sources produce mentions at the same rate. The dataset includes structurally different source types, and "zero mentions" can be a correct result rather than a pipeline defect.

**CISA KEV: structural zero rate.** The CISA Known Exploited Vulnerabilities catalog produced zero ATT&CK technique mentions across the initial 1,592 entries (verified independently via Postgres regex against `extracted_text`). This is expected and not a pipeline defect. KEV entries describe vulnerabilities (CVE, vendor, required action) rather than exploitation behavior. ATT&CK references live in incident reports and threat actor profiles, not vulnerability catalogs. KEV is retained in the dataset as pivot data — CVEs from KEV are cross-referenced against mention-bearing sources to identify which exploitation campaigns target actively-exploited vulnerabilities.

**CISA Advisories (AA-numbered): high-yield, structured.** Joint Cybersecurity Advisories often include explicit ATT&CK technique tables that CISA themselves prepared. The ingester extracts mentions from these tables with `extraction_method = 'cisa_attack_table'` and confidence 1.0, distinct from regex-extracted mentions. Advisories without explicit tables fall through to the standard regex extractor over the body prose.

The two extraction methods are stored separately so analytical queries can choose their precision tier. A query like "techniques present in CISA-curated tables" uses the table-extracted mentions only; a query like "all technique references regardless of how they were extracted" uses both.

## Why these choices

The two-stage approach (regex + spaCy) is a deliberate precision/recall tradeoff. A pure-regex pipeline misses most mentions. A pure-NLP pipeline introduces too much noise. Stratifying by extraction method in the database lets downstream queries choose their own precision/recall point.

Empirical validation is included because trend claims without confidence intervals are not trend claims, they're guesses with charts.
