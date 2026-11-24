# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Native dependency advisory assessment and optional existing BEAM evidence.
- Flow-derived candidates, security boundary review, and expanded evidence queries.
- Source/dependency finding projections and cross-run comparison.
- Run inventory, explicit deletion and age/count pruning with dry-run previews.
- Per-run filesystem guards for public run operations and cleanup.

### Changed

- Default review concurrency and budget reduced; pause after provider errors.
- Store runs in configurable XDG user state; support only the current schema.
- Persist follow-up evidence and support explicit unresolved reconsideration.
