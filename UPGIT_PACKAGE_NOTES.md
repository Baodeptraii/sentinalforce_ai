# Package notes

Source copied from authorized lab project directories into this local staging directory.

Excluded by design: host credentials, `.env`, local config, virtual environments, runtime outputs, audit/execution history, backups, reports, generated indexes, SQLite catalog, embeddings, archives, and machine-specific lab evidence.

Before GitHub upload:

1. Review source paths and scenario data.
2. Run secret scan on working tree and Git history.
3. Install dependencies in an external virtual environment.
4. Run offline tests only.
5. Inspect `git diff --cached` before commit.

Current package is staging-only. No GitHub remote, commit, or push performed.
