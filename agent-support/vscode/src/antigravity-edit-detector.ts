import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export type AntigravityEditMatch = {
  conversationId: string;
  transcriptPath: string;
  model: string;
  toolUseId: string;
};

export type AntigravityCompletedEdit = AntigravityEditMatch & {
  filePath: string;
};

type TranscriptRecord = {
  step_index?: number;
  created_at?: string;
  type?: string;
  content?: string;
  tool_calls?: Array<{
    name?: string;
    args?: Record<string, unknown>;
  }>;
};

export class AntigravityEditDetector {
  private consumed = new Set<string>();

  constructor(
    private readonly brainRoot = path.join(os.homedir(), ".gemini", "antigravity-ide", "brain"),
    private readonly now = () => Date.now(),
    private readonly maxAgeMs = 60_000,
  ) {}

  public findRecentEdit(filePath: string): AntigravityEditMatch | null {
    let conversationIds: string[];
    try {
      conversationIds = fs.readdirSync(this.brainRoot);
    } catch {
      return null;
    }

    const normalizedTarget = path.resolve(filePath);
    let best: { match: AntigravityEditMatch; timestamp: number; key: string } | null = null;

    for (const conversationId of conversationIds) {
      const transcriptPath = path.join(
        this.brainRoot,
        conversationId,
        ".system_generated",
        "logs",
        "transcript.jsonl",
      );
      let stat: fs.Stats;
      try {
        stat = fs.statSync(transcriptPath);
      } catch {
        continue;
      }
      if (this.now() - stat.mtimeMs > this.maxAgeMs) {
        continue;
      }

      let records: TranscriptRecord[];
      try {
        records = fs.readFileSync(transcriptPath, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as TranscriptRecord);
      } catch {
        continue;
      }

      const model = extractModel(records);
      for (const record of records) {
        if (record.type !== "PLANNER_RESPONSE" || !record.created_at) {
          continue;
        }
        const timestamp = Date.parse(record.created_at);
        if (!Number.isFinite(timestamp) || this.now() - timestamp > this.maxAgeMs) {
          continue;
        }
        for (const call of record.tool_calls ?? []) {
          if (!isWriteTool(call.name)) {
            continue;
          }
          const candidate = normalizeTargetFile(call.args?.TargetFile ?? call.args?.target_file ?? call.args?.file_path);
          if (!candidate || path.resolve(candidate) !== normalizedTarget) {
            continue;
          }
          const toolUseId = `step-${record.step_index ?? "unknown"}`;
          const key = `${conversationId}:${normalizedTarget}:${toolUseId}`;
          if (this.consumed.has(key)) {
            continue;
          }
          if (!best || timestamp > best.timestamp) {
            best = {
              timestamp,
              key,
              match: { conversationId, transcriptPath, model, toolUseId },
            };
          }
        }
      }
    }

    if (!best) {
      return null;
    }
    this.consumed.add(best.key);
    return best.match;
  }

  public findCompletedEdits(transcriptPath: string): AntigravityCompletedEdit[] {
    let records: TranscriptRecord[];
    let stat: fs.Stats;
    try {
      stat = fs.statSync(transcriptPath);
      records = fs.readFileSync(transcriptPath, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as TranscriptRecord);
    } catch {
      return [];
    }
    if (this.now() - stat.mtimeMs > this.maxAgeMs) {
      return [];
    }

    const relative = path.relative(this.brainRoot, transcriptPath);
    const conversationId = relative.split(path.sep)[0];
    if (!conversationId || conversationId.startsWith("..")) {
      return [];
    }
    const model = extractModel(records);
    const edits: AntigravityCompletedEdit[] = [];
    for (const record of records) {
      if (record.type !== "CODE_ACTION" || typeof record.content !== "string" || !record.created_at) {
        continue;
      }
      const timestamp = Date.parse(record.created_at);
      if (!Number.isFinite(timestamp) || this.now() - timestamp > this.maxAgeMs) {
        continue;
      }
      const filePath = filePathFromCompletedAction(record.content);
      if (!filePath) {
        continue;
      }
      const toolUseId = `step-${record.step_index ?? "unknown"}`;
      const key = `${conversationId}:${path.resolve(filePath)}:${toolUseId}`;
      if (this.consumed.has(key)) {
        continue;
      }
      this.consumed.add(key);
      edits.push({ conversationId, transcriptPath, model, toolUseId, filePath });
    }
    return edits;
  }

  public watchCompletedEdits(onEdit: (edit: AntigravityCompletedEdit) => void): fs.FSWatcher | null {
    try {
      const pending = new Map<string, NodeJS.Timeout>();
      const watcher = fs.watch(this.brainRoot, { recursive: true }, (_event, filename) => {
        if (!filename || !filename.endsWith(path.join("logs", "transcript.jsonl"))) {
          return;
        }
        const transcriptPath = path.join(this.brainRoot, filename);
        const existing = pending.get(transcriptPath);
        if (existing) {
          clearTimeout(existing);
        }
        pending.set(transcriptPath, setTimeout(() => {
          pending.delete(transcriptPath);
          for (const edit of this.findCompletedEdits(transcriptPath)) {
            onEdit(edit);
          }
        }, 250));
      });
      watcher.on("close", () => {
        for (const timer of pending.values()) {
          clearTimeout(timer);
        }
        pending.clear();
      });
      return watcher;
    } catch {
      return null;
    }
  }
}

function isWriteTool(name: string | undefined): boolean {
  return name === "write_to_file" || name === "replace_file_content" || name === "multi_replace_file_content";
}

function normalizeTargetFile(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  let normalized = value.trim();
  if (normalized.startsWith('"') && normalized.endsWith('"')) {
    normalized = normalized.slice(1, -1);
  }
  if (normalized.startsWith("file://")) {
    try {
      normalized = new URL(normalized).pathname;
    } catch {
      return null;
    }
  }
  return normalized || null;
}

function extractModel(records: TranscriptRecord[]): string {
  const pattern = /changed setting `Model Selection` from .*? to (.+?)\. No need/s;
  let model = "unknown";
  for (const record of records) {
    if (record.type !== "USER_INPUT" || typeof record.content !== "string") {
      continue;
    }
    const match = pattern.exec(record.content);
    if (match?.[1]) {
      model = match[1].trim();
    }
  }
  return model;
}

function filePathFromCompletedAction(content: string): string | null {
  const match = /(?:Created|Edited|Modified|Deleted) file (file:\/\/\/[^\s]+?)(?:\s|$)/i.exec(content);
  if (!match?.[1]) {
    return null;
  }
  try {
    return decodeURIComponent(new URL(match[1]).pathname);
  } catch {
    return null;
  }
}
