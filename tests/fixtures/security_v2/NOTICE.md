# Fixture notice

The finding and enforcement fixtures contain adapted material from
[Numbat](https://github.com/perplexityai/numbat), commit `20a5a52`, licensed
under the Apache License 2.0.

- `valid-finding.json` and `valid-enforcement.json` are privacy-reduced
  projections of one deterministic replay of pinned
  `TestHookWritesFindingToFileSinkNotStdout`. That integration test invokes the
  real Codex pre-tool hook with `cat .env` and proves that the file sink writes
  a `secrets.agent_read_env` 1.3 finding followed by a joined
  `no_override`/`monitor` enforcement record.
- The replay fixes the otherwise random Numbat run ID at
  `run-20261017T100000.000000000-0123456789abcdef`. The resulting action event
  ID is `hook-run-20261017T100000.000000000-0123456789abcdef`, the finding ID is
  `fnd-49e7e870ff96953b2b8e5dd3`, and the enforcement ID is
  `enf-8f62f739638bc81b28547bc9`. These values are reproduced from pinned
  `hookEventID`, `internal/finding/finding.go:findingID`, and
  `cmd/numbat/hook.go:hookDecisionID`. Before TrackAI projection, the source
  enforcement's `finding_ids` contains that finding ID and its
  `action_event_ids` equals the finding's cited event ID.
- `cmd/numbat/testdata/secrets_fixture.ndjson` event `e1` independently supplies
  the same real stream action (`cat .env`) and built-in rule match. It does not
  supply an enforcement record: Numbat enforcement is hook-only. The paired
  enforcement fixture therefore comes from the pinned persisted-hook test,
  not from the artifact NDJSON stream.
- `valid-rule-bundle.json` embeds the exact valid operator rule used by pinned
  Numbat's `TestRulesCheckRunsCompanionTestsAgainstBuiltinOverride`; that test
  executes `numbat rules check` successfully.

Paths, host names, user names, tenant identity, machine identity, session
identity and lease identity are omitted or replaced with explicit placeholders.
No secret, raw tool input, raw tool result, message content or evidence payload
is retained.

The remaining fixtures are original TrackAI contract examples. Numbat field
names and enum meanings are still governed by the source attribution in the
parent contract README.
