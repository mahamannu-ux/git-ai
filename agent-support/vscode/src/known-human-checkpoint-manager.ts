import * as vscode from "vscode";
import * as path from "node:path";
import { spawn } from "child_process";
import { getGitAiBinary } from "./utils/binary-path";
import { getGitRepoRoot } from "./utils/git-api";
import {
  AntigravityCompletedEdit,
  AntigravityEditDetector,
  AntigravityEditMatch,
} from "./antigravity-edit-detector";

/**
 * Fires a `git-ai checkpoint known_human --hook-input stdin` whenever a
 * document is saved. Debounces per repo root over a 500ms window so that
 * bulk saves (e.g. "Save All") are batched into one checkpoint call.
 *
 * Skips non-file-scheme documents and .vscode/ internal files.
 */
export class KnownHumanCheckpointManager {
  private readonly debounceMs = 500;

  // per repo root: pending debounce timer
  private pendingTimers = new Map<string, NodeJS.Timeout>();

  // per repo root: set of absolute file paths queued in current debounce window
  private pendingPaths = new Map<string, Set<string>>();

  // Explicit content snapshots for events where the path can no longer be
  // read from disk (notably workspace file deletion). An empty string means
  // the file's current content is empty/deleted; presence in the map matters.
  private pendingContentOverrides = new Map<string, Map<string, string>>();
  private readonly antigravityDetector: AntigravityEditDetector | null;
  private readonly antigravityWatcher: import("node:fs").FSWatcher | null;

  constructor(
    private readonly editorVersion: string,
    private readonly extensionVersion: string,
    antigravityEnabled = false,
  ) {
    this.antigravityDetector = antigravityEnabled ? new AntigravityEditDetector() : null;
    this.antigravityWatcher = this.antigravityDetector?.watchCompletedEdits((edit) => {
      this.handleCompletedAntigravityEdit(edit).catch((error) => {
        console.error("[git-ai] Antigravity transcript checkpoint failed", error);
      });
    }) ?? null;
  }

  private async handleCompletedAntigravityEdit(edit: AntigravityCompletedEdit): Promise<void> {
    const uri = vscode.Uri.file(edit.filePath);
    const repoRoot = getGitRepoRoot(uri)
      ?? vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath
      ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!repoRoot) {
      console.warn("[git-ai] Antigravity edit has no workspace/repository root", edit.filePath);
      return;
    }

    let content = "";
    try {
      const document = vscode.workspace.textDocuments.find(
        (candidate) => candidate.uri.fsPath === edit.filePath && candidate.uri.scheme === "file"
      );
      content = document
        ? document.getText()
        : Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
    } catch {
      // A confirmed delete action intentionally has empty current content.
    }

    const hookInput = JSON.stringify({
      cwd: repoRoot,
      conversation_id: edit.conversationId,
      model: edit.model,
      transcript_path: edit.transcriptPath,
      tool_use_id: edit.toolUseId,
      edited_filepaths: [edit.filePath],
      dirty_files: { [edit.filePath]: content },
    });
    console.log("[git-ai] Dispatching confirmed Antigravity CODE_ACTION for", edit.filePath);
    await this.spawnCheckpoint(repoRoot, "antigravity", hookInput);
  }

  public handleSaveEvent(doc: vscode.TextDocument): void {
    if (doc.uri.scheme !== "file") {
      return;
    }

    const filePath = doc.uri.fsPath;

    if (this.isInternalVSCodePath(filePath)) {
      console.log("[git-ai] KnownHumanCheckpointManager: Ignoring internal VSCode file:", filePath);
      return;
    }

    const repoRoot = getGitRepoRoot(doc.uri);
    if (!repoRoot) {
      console.log("[git-ai] KnownHumanCheckpointManager: No git repo found for", filePath, "- skipping");
      return;
    }

    this.queuePath(repoRoot, filePath);
  }

  public handleDeleteEvent(event: vscode.FileDeleteEvent): void {
    for (const uri of event.files) {
      if (uri.scheme !== "file" || this.isInternalVSCodePath(uri.fsPath)) {
        continue;
      }
      const repoRoot = getGitRepoRoot(uri);
      if (!repoRoot) {
        console.log("[git-ai] KnownHumanCheckpointManager: No git repo found for deleted path", uri.fsPath, "- skipping");
        continue;
      }
      this.queuePath(repoRoot, uri.fsPath, "");
    }
  }

  private queuePath(repoRoot: string, filePath: string, contentOverride?: string): void {
    // Accumulate file into pending set for this repo root
    let pending = this.pendingPaths.get(repoRoot);
    if (!pending) {
      pending = new Set();
      this.pendingPaths.set(repoRoot, pending);
    }
    pending.add(filePath);

    if (contentOverride !== undefined) {
      let overrides = this.pendingContentOverrides.get(repoRoot);
      if (!overrides) {
        overrides = new Map();
        this.pendingContentOverrides.set(repoRoot, overrides);
      }
      overrides.set(filePath, contentOverride);
    }

    // Reset debounce timer
    const existing = this.pendingTimers.get(repoRoot);
    if (existing) {
      clearTimeout(existing);
    }

    const timer = setTimeout(() => {
      this.executeCheckpoint(repoRoot).catch((err) =>
        console.error("[git-ai] KnownHumanCheckpointManager: Checkpoint error:", err)
      );
    }, this.debounceMs);

    this.pendingTimers.set(repoRoot, timer);
    console.log("[git-ai] KnownHumanCheckpointManager: File change queued for", filePath);
  }

  private async executeCheckpoint(repoRoot: string): Promise<void> {
    this.pendingTimers.delete(repoRoot);

    const paths = this.pendingPaths.get(repoRoot);
    if (!paths || paths.size === 0) {
      return;
    }
    const snapshot = [...paths];
    paths.clear();
    const contentOverrides = this.pendingContentOverrides.get(repoRoot);
    this.pendingContentOverrides.delete(repoRoot);

    // Build dirty_files as absolute path → current content
    const dirtyFiles: Record<string, string> = {};
    for (const absolutePath of snapshot) {
      if (contentOverrides?.has(absolutePath)) {
        dirtyFiles[absolutePath] = contentOverrides.get(absolutePath)!;
        continue;
      }
      const doc = vscode.workspace.textDocuments.find(
        (d) => d.uri.fsPath === absolutePath && d.uri.scheme === "file"
      );

      let content: string | null = null;
      if (doc) {
        // Use open document buffer if available (handles codespaces/remote lag)
        content = doc.getText();
      } else {
        // Fall back to reading from disk if document was closed within debounce window
        try {
          const bytes = await vscode.workspace.fs.readFile(vscode.Uri.file(absolutePath));
          content = Buffer.from(bytes).toString("utf-8");
        } catch (err) {
          console.error("[git-ai] KnownHumanCheckpointManager: Failed to read file", absolutePath, err);
        }
      }

      if (content !== null) {
        dirtyFiles[absolutePath] = content;
      }
    }

    if (Object.keys(dirtyFiles).length === 0) {
      return;
    }

    const editedFilepaths = Object.keys(dirtyFiles);

    const antigravityGroups = new Map<string, {
      match: AntigravityEditMatch;
      paths: string[];
    }>();
    const humanPaths: string[] = [];
    for (const absolutePath of editedFilepaths) {
      const match = this.antigravityDetector?.findRecentEdit(absolutePath) ?? null;
      if (!match) {
        humanPaths.push(absolutePath);
        continue;
      }
      const key = `${match.conversationId}:${match.model}:${match.transcriptPath}`;
      const group = antigravityGroups.get(key) ?? { match, paths: [] };
      group.paths.push(absolutePath);
      antigravityGroups.set(key, group);
    }

    for (const { match, paths } of antigravityGroups.values()) {
      const antigravityDirtyFiles = Object.fromEntries(
        paths.map((filePath) => [filePath, dirtyFiles[filePath]])
      );
      const hookInput = JSON.stringify({
        cwd: repoRoot,
        conversation_id: match.conversationId,
        model: match.model,
        transcript_path: match.transcriptPath,
        tool_use_id: match.toolUseId,
        edited_filepaths: paths,
        dirty_files: antigravityDirtyFiles,
      });
      console.log("[git-ai] KnownHumanCheckpointManager: Reclassifying recent Antigravity edit for", paths);
      await this.spawnCheckpoint(repoRoot, "antigravity", hookInput);
    }

    if (humanPaths.length === 0) {
      return;
    }

    const humanDirtyFiles = Object.fromEntries(
      humanPaths.map((filePath) => [filePath, dirtyFiles[filePath]])
    );

    const hookInput = JSON.stringify({
      editor: "vscode",
      editor_version: this.editorVersion,
      extension_version: this.extensionVersion,
      cwd: repoRoot,
      edited_filepaths: humanPaths,
      dirty_files: humanDirtyFiles,
    });

    console.log("[git-ai] KnownHumanCheckpointManager: Firing known_human checkpoint for", humanPaths);

    await this.spawnCheckpoint(repoRoot, "known_human", hookInput);
  }

  private spawnCheckpoint(repoRoot: string, preset: string, hookInput: string): Promise<void> {
    return new Promise((resolve) => {
      const proc = spawn(getGitAiBinary(), ["checkpoint", preset, "--hook-input", "stdin"], {
        cwd: repoRoot,
      });

      let stdout = "";
      let stderr = "";

      proc.stdout.on("data", (data) => { stdout += data.toString(); });
      proc.stderr.on("data", (data) => { stderr += data.toString(); });

      proc.on("error", (err) => {
        console.error("[git-ai] KnownHumanCheckpointManager: Spawn error:", err.message);
        resolve();
      });

      proc.on("close", (code) => {
        if (code !== 0) {
          console.error("[git-ai] KnownHumanCheckpointManager: Checkpoint exited with code", code, stdout, stderr);
        } else {
          console.log("[git-ai] KnownHumanCheckpointManager: Checkpoint succeeded", stdout.trim());
        }
        resolve();
      });

      proc.stdin.write(hookInput);
      proc.stdin.end();
    });
  }

  private isInternalVSCodePath(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, "/");
    return normalized.includes("/.vscode/");
  }

  public dispose(): void {
    this.antigravityWatcher?.close();
    for (const timer of this.pendingTimers.values()) {
      clearTimeout(timer);
    }
    this.pendingTimers.clear();
    this.pendingPaths.clear();
    this.pendingContentOverrides.clear();
  }
}
