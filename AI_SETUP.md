# Local setup

Copy example configuration files before running. Keep credentials outside repository.

- GUI: copy `GUI/config.example.json` to `GUI/config.json`, then set lab scope and CALDERA key path locally.
- Scenario Agent: copy `scenario_agent/.env.example` to `scenario_agent/.env`, then set provider key locally if live planning is authorized.
- Do not commit `config.json`, `.env`, host files, API keys, cookies, or runtime output.

Default package layout expects `GUI/` and `scenario_agent/` as sibling directories. GUI `scenario_root` may point to `../scenario_agent`.
