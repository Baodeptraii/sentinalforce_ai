# Survey → Scenario integration, 17/11/2026

Deployment: local checkout under `GUI/`; configure deployment host and service outside repository.
Scenario runtime/catalog/index configured by local deployment; build derived catalog/index from included source when needed.

## Use

Open `http://127.0.0.1:8765` on deployment host. For remote access, use an administrator-approved SSH tunnel to that host; keep hostnames and credentials outside repository.

Complete Survey for a configured lab target, transfer its profile to Scenario, enter a concrete behavior, select endpoint/web and maximum steps, then click **Sinh kế hoạch AI**. Existing survey profiles and uploaded profiles are also supported.tory retains results after refresh. For missing information or temporary provider errors, use **Tiếp tục lượt này** with clarification when required.

Scenario remains planning-only. A completed generation is a validated, grounded plan, not evidence of execution or SOC detection. Downloaded `ScenarioPlan` retains prerequisite/parameter limitations; it is not automatically submitted to CALDERA.

## Components and contracts

- `engine/scenario_bridge.py`: asynchronous jobs, one planning worker at a time, input validation, handoff/evidence hash checks, policy adapter, bounded 15-minute subprocess, download allowlist, history and resume.
- `engine/scenario_worker.py`: invokes existing LangGraph Scenario workflow using its own Python environment; checks selected scope and step limits; retains checkpoint and provider error states.
- `app.py`: adds `/api/scenarios`, `/api/scenarios/<id>`, `/api/scenarios/<id>/resume`, and allowlisted artifact downloads with existing CSRF protection.
- `static/scenario.js`, `static/index.html`: real AI generation, progress, errors, history, resume and downloads. Library remains a reference collection; it is not a selectable subset of the live catalog.
- Adapter `survey_scenario_adapter_v1`: preserves original profile/unknowns; creates a separate planning target with legacy `execution_scope` fields explicitly marked planning-only and `execution_authorized=false`. Does not invent dummy paths or credentials.
- Each job under `GUI/scenario_outputs/<id>` contains original profile, adapted profile, policy, request, provenance, workflow runs/checkpoints, result and validated YAML when successful. Matched local survey handoffs are hash checked; unmatched uploads are labeled unverified.
- Collector v5 reads bounded Apache access-log metadata from XAMPP/observed httpd locations without Wazuh configuration. New ability/adversary IDs end `0033`/`0034`; v4 definitions retained.

## Verification and limitations

- Existing index check: valid fingerprints/normalized vectors, 2,081 vectors, 384 dimensions.
- Six bridge tests pass: preserved observations/unknowns, invalid policy inputs, network scope, evidence hashes, traversal, concurrency, completed-run resume rejection.
- JavaScript checks are historical and must be rerun from the included test files; deployment screenshots and logs are outside package staging.
- Browser desktop/mobile: profile selection, history, completed YAML, download, no horizontal overflow, no JS errors, live request submission.
- Two real endpoint planning jobs completed with grounded T1057 plans: `5451aea9e5374965a598f1f1c0fbb059` (terminal submission text suffered local encoding loss; not used as Vietnamese UX evidence), `3004dbcfd0e14a80bfde2f323fdeda4a` (Vietnamese browser submission).
- Survey v5 run `40cc3fb94ce94e5a9f22918f9d4d4e7b` completed with local process/network/web access-log evidence true; Wazuh ingestion null. Original survey `8722ef963d82403fb445ed9c0f8e9f05` remains unchanged.
- Python legacy suite: 82/83 pass. The pre-existing replay fixture mismatch remains (8 requests/6 observations vs expected 11/9), also observed before integration; not hidden or patched to force a pass.
- LLM availability is external: HTTP 503 results in `waiting_service` with checkpoint and explicit resume. No model substitution.
- End-to-end v5 Survey profile to endpoint Scenario: job `202ffba3347247dfb26a6e73daf09058` completed after the browser resume action recovered from HTTP 503; validation errors are empty, readiness remains `needs_information`. Evidence is copied into local `evidence/`.
- Web planning job `201b3dab37eb4171bef5fd2cfbc734e1` reached planning after retrieval/grounding, but remains `waiting_service` (Gemini HTTP 503) after one explicit resume. Web plan completion is not verified. Its checkpoint is retained for the next resume.
- Deployment health checks and screenshots are outside package staging; rerun them in deployment workspace before release.
- Wazuh integration and scenario execution are not implemented by this change. Readiness remains `needs_information` where prerequisites are unverified.

## Recovery

Keep deployment backups, outputs, and scenario outputs outside this repository. For rollback, stop GUI, compare the saved source backup, restore only reviewed files, then start service. Do not delete historic evidence or local runtime data.

```bash
systemctl --user status datn-survey.service
journalctl --user -u datn-survey.service -n 50
systemctl --user restart datn-survey.service
```

Local source snapshots, test logs and browser screenshots are not included in package staging. No secrets belong in this report.
