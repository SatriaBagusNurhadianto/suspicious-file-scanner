# Changelog

## [0.2.0] - 2026-11-05

### Added
- YARA rule matching (`match_yara`) integrated into scan reports.
- Local SQLite scan history with bounded retention (count + age) and purge.
- Relationship graph between scanned files (in-memory, bounded, iterative BFS).

### Security
- Hardened export path validation (`_safe_dest`): traversal, broken/existing symlinks, TOCTOU re-validation, oversized paths.
- Hardened `_pdf_escape`: control characters stripped from PDF text stream.
- YARA target size caps and post-read guards.
- Scan history path validation and retention purge.
- Relationship graph node_id/key caps and clamped limits.

### Tests
- 96 passed, 3 skipped (platform-gated).
- Dedicated coverage for exporter, strings, YARA matcher, history, and graph modules.
