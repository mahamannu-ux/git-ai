import * as assert from "node:assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { AntigravityEditDetector } from "../antigravity-edit-detector";

suite("Antigravity edit detector", () => {
  test("matches a recent write action and extracts model identity once", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "git-ai-antigravity-"));
    const conversationId = "conversation-123";
    const logDir = path.join(root, conversationId, ".system_generated", "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const target = path.join(root, "repo", "src", "fixture.py");
    const now = Date.now();
    const transcript = [
      {
        step_index: 0,
        type: "USER_INPUT",
        created_at: new Date(now - 2_000).toISOString(),
        content: "The user changed setting `Model Selection` from None to Gemini 3.5 Flash (Low). No need to comment.",
      },
      {
        step_index: 6,
        type: "PLANNER_RESPONSE",
        created_at: new Date(now - 1_000).toISOString(),
        tool_calls: [{ name: "write_to_file", args: { TargetFile: JSON.stringify(target) } }],
      },
    ].map((record) => JSON.stringify(record)).join("\n");
    fs.writeFileSync(path.join(logDir, "transcript.jsonl"), transcript);

    const detector = new AntigravityEditDetector(root, () => now);
    const match = detector.findRecentEdit(target);
    assert.ok(match);
    assert.strictEqual(match.conversationId, conversationId);
    assert.strictEqual(match.model, "Gemini 3.5 Flash (Low)");
    assert.strictEqual(match.toolUseId, "step-6");
    assert.strictEqual(detector.findRecentEdit(target), null);
  });

  test("does not claim stale or unrelated saves", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "git-ai-antigravity-"));
    const logDir = path.join(root, "conversation-old", ".system_generated", "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const now = Date.now();
    fs.writeFileSync(path.join(logDir, "transcript.jsonl"), JSON.stringify({
      step_index: 1,
      type: "PLANNER_RESPONSE",
      created_at: new Date(now - 120_000).toISOString(),
      tool_calls: [{ name: "write_to_file", args: { TargetFile: '"/repo/other.py"' } }],
    }));
    const old = new Date(now - 120_000);
    fs.utimesSync(path.join(logDir, "transcript.jsonl"), old, old);

    const detector = new AntigravityEditDetector(root, () => now);
    assert.strictEqual(detector.findRecentEdit("/repo/fixture.py"), null);
  });

  test("emits only confirmed code actions and decodes file URLs", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "git-ai-antigravity-"));
    const conversationId = "conversation-completed";
    const logDir = path.join(root, conversationId, ".system_generated", "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const now = Date.now();
    const target = "/repo/path with spaces/fixture.py";
    const transcriptPath = path.join(logDir, "transcript.jsonl");
    fs.writeFileSync(transcriptPath, [
      {
        step_index: 0,
        type: "USER_INPUT",
        created_at: new Date(now - 2_000).toISOString(),
        content: "The user changed setting `Model Selection` from None to Claude Sonnet 4. No need to comment.",
      },
      {
        step_index: 2,
        type: "PLANNER_RESPONSE",
        created_at: new Date(now - 1_500).toISOString(),
        tool_calls: [{ name: "write_to_file", args: { TargetFile: JSON.stringify(target) } }],
      },
      {
        step_index: 3,
        type: "CODE_ACTION",
        created_at: new Date(now - 1_000).toISOString(),
        content: `Created file ${new URL(`file://${target}`).toString()} with requested content.`,
      },
    ].map((record) => JSON.stringify(record)).join("\n"));

    const detector = new AntigravityEditDetector(root, () => now);
    const edits = detector.findCompletedEdits(transcriptPath);
    assert.strictEqual(edits.length, 1);
    assert.strictEqual(edits[0].filePath, target);
    assert.strictEqual(edits[0].conversationId, conversationId);
    assert.strictEqual(edits[0].model, "Claude Sonnet 4");
    assert.deepStrictEqual(detector.findCompletedEdits(transcriptPath), []);
  });
});
