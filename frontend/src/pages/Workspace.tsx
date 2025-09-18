import { useCallback, useState } from "react";
import { api } from "../api/client";
import type { PolicyDecision } from "../api/client";
import { useApi } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

interface WorkspaceEntry {
  name: string;
  path: string;
  type: "file" | "directory";
  size: number | null;
  symlink: boolean;
}

interface BrowseResponse {
  path: string;
  allowed: boolean;
  decision: PolicyDecision;
  entries: WorkspaceEntry[];
}

interface FileResponse {
  path: string;
  allowed: boolean;
  decision: PolicyDecision;
  content: string | null;
  bytes?: number;
}

export function WorkspacePage() {
  const [path, setPath] = useState("documents");
  const [selected, setSelected] = useState<string | null>(null);
  const [file, setFile] = useState<FileResponse | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const browse = useApi<BrowseResponse>(
    (signal) => api.get(`/workspace?path=${encodeURIComponent(path)}`, signal),
    [path],
  );

  const openFile = useCallback(async (entryPath: string) => {
    setSelected(entryPath);
    setFileError(null);
    try {
      const data = await api.get<FileResponse>(
        `/workspace/file?path=${encodeURIComponent(entryPath)}`,
      );
      setFile(data);
    } catch (caught) {
      setFile(null);
      setFileError(caught instanceof Error ? caught.message : String(caught));
    }
  }, []);

  const directories = browse.data?.entries.filter((entry) => entry.type === "directory") ?? [];
  const files = browse.data?.entries.filter((entry) => entry.type === "file") ?? [];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Approved workspace</h1>
        <p className="text-sm text-ink-muted">
          The only directory tree an AI agent may inspect. Listing and reading use the same
          path resolver and the same policy engine as the agent tools, so the view matches
          exactly what the agent can reach.
        </p>
      </header>

      <Card title="Browse" bodyClassName="p-5 space-y-4">
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[240px] flex-1">
            <label className="label" htmlFor="workspace-path">
              Workspace path
            </label>
            <input
              id="workspace-path"
              className="field font-mono text-xs"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") browse.reload();
              }}
            />
          </div>
          <button type="button" className="btn-secondary" onClick={browse.reload}>
            List
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              setPath(".");
              setSelected(null);
              setFile(null);
            }}
          >
            Workspace root
          </button>
        </div>

        {browse.loading ? (
          <Spinner />
        ) : browse.error ? (
          <ErrorState message={browse.error} onRetry={browse.reload} />
        ) : browse.data && !browse.data.allowed ? (
          <div className="rounded-lg border border-danger/30 bg-danger/5 p-4">
            <p className="text-sm font-semibold text-danger">
              Denied by rule {browse.data.decision.rule_id}
            </p>
            <p className="mt-1 text-sm text-ink-muted">{browse.data.decision.reason}</p>
            <ul className="mt-2 space-y-1 text-xs text-ink-faint">
              {browse.data.decision.explanation.map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>
        ) : (
          <>
            {directories.length > 0 && (
              <div>
                <p className="label">Directories</p>
                <div className="flex flex-wrap gap-2">
                  {directories.map((entry) => (
                    <button
                      key={entry.path}
                      type="button"
                      className="btn-secondary btn-sm font-mono"
                      onClick={() => setPath(entry.path)}
                    >
                      ▦ {entry.name}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div>
              <p className="label">Files</p>
              {files.length === 0 ? (
                <EmptyState title="No files in this directory" />
              ) : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Path</th>
                        <th scope="col">Size</th>
                        <th scope="col">Flags</th>
                        <th scope="col">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((entry) => (
                        <tr key={entry.path} className={selected === entry.path ? "bg-brand/5" : ""}>
                          <td className="font-mono text-xs">{entry.name}</td>
                          <td className="font-mono text-xs text-ink-muted">{entry.path}</td>
                          <td className="tabular-nums text-xs">
                            {entry.size === null ? "—" : `${entry.size} B`}
                          </td>
                          <td>
                            {entry.symlink && <Badge tone="warn">symlink</Badge>}
                          </td>
                          <td className="text-right">
                            <button
                              type="button"
                              className="btn-secondary btn-sm"
                              onClick={() => void openFile(entry.path)}
                            >
                              Open
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}
      </Card>

      {fileError && <ErrorState message={fileError} />}
      {file && (
        <Card
          title={file.path}
          subtitle={file.allowed ? `${file.bytes ?? 0} bytes` : "Access denied"}
          actions={<StatusBadge status={file.allowed ? "allowed" : "denied"} />}
          bodyClassName="p-0"
        >
          {file.allowed ? (
            <pre className="code-block m-5 max-h-[520px] whitespace-pre-wrap">{file.content}</pre>
          ) : (
            <div className="p-5">
              <p className="text-sm text-ink-muted">{file.decision.reason}</p>
              <ul className="mt-2 space-y-1 text-xs text-ink-faint">
                {file.decision.explanation.map((line) => (
                  <li key={line}>• {line}</li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
