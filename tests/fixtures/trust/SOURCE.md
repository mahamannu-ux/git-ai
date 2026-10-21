# Source of the trust vectors

- Repository: TrackAI (`~/AIProjects/TrackAI-v1`, read-only for this session)
- Path: `apps/api/src/features/attesta/vectors/trust/`
- Commit: `67af03726a86c94ff1de766059bebd1a7147add9` (TrackAI `main`)
- Files: all 82 `NN-*.json` cross-language vectors plus `keys.json`, copied byte for byte.
  (`generate.ts` in that folder shows how they were made; it is not ported.)
- Provenance: the TypeScript verifier under test was itself ported from
  SushiCorp B4 `core/trust/{revocation,verdict}.py` @ `0bd67a5` (catalog TR-1).
