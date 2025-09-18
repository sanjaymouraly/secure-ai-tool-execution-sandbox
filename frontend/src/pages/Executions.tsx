import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi, formatDuration, formatTimestamp } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

interface ExecutionRow {
  id: string;
  session_id: string | null;
  trace_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  status: string;
  decision: string;
  reason: string;
  policy_rule_id: string;
  policy_version: string;
  approved_by: string | null;
  output: string;
  error: string | null;
  exit_code: number;
  duration_ms: number;
  output_bytes: number;
  sandbox_id: string;
  sandbox_backend: string;
  timed_out: boolean;
  truncated: boolean;
  created_at: string;
}

const STATUS_FILTERS = ["", "completed", "denied", "failed", "awaiting_approval", "timeout"];

export function ExecutionsPage() {
  const [params, setParams] = useSearchParams();
  const [statusFilter, setStatusFilter] = useState(params.get("status") ?? "");
  const [toolFilter, setToolFilter] = useState("");
  const [selected, setSelected] = useState<ExecutionRow | null>(null);

  const sessionId = params.get("session") ?? "";
  const query = new URLSearchParams();
  if (statusFilter) query.set("status", statusFilter);
  if (toolFilter) query.set("tool_name", toolFilter);
  if (sessionId) query.set("session_id", sessionId);
  query.set("limit", "200");

  const { data, loading, error, reload } = useApi<{ executions: ExecutionRow[]; count: number }>(
    (signal) => api.get(`/executions?${query.toString()}`, signal),
    [statusFilter, toolFilter, sessionId],
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Executions</h1>
          <p className="text-sm text-ink-muted">
            Every tool invocation with its policy decision, sandbox identity and result.
          </p>
        </div>
        {sessionId && (
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={() => {
              params.delete("session");
              setParams(params);
            }}
          >
            Clear session filter
          </button>
        )}
      </header>

      <Card title="Filters" bodyClassName="p-5">
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <label className="label" htmlFor="status-filter">
              Status
            </label>
            <select
              id="status-filter"
              className="field"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              {STATUS_FILTERS.map((value) => (
                <option key={value || "all"} value={value}>
                  {value ? value.replace(/_/g, " ") : "all"}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="tool-filter">
              Tool
            </label>
            <input
              id="tool-filter"
              className="field font-mono text-xs"
              placeholder="read_file"
              value={toolFilter}
              onChange={(event) => setToolFilter(event.target.value)}
            />
          </div>
          <div className="flex items-end">
            <button type="button" className="btn-secondary" onClick={reload}>
              Refresh
            </button>
          </div>
        </div>
      </Card>

      {loading ? (
        <Spinner label="Loading executions" />
      ) : error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : !data || data.executions.length === 0 ? (
        <Card title="Executions" bodyClassName="p-0">
          <EmptyState
            title="No executions match these filters"
            description="Invoke a tool from the tool registry or run the agent to populate the history."
          />
        </Card>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <Card title={`Executions (${data.count})`} bodyClassName="p-0">
            <div className="table-wrap max-h-[720px] overflow-y-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Tool</th>
                    <th scope="col">Status</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Duration</th>
                    <th scope="col">When</th>
                  </tr>
                </thead>
                <tbody>
                  {data.executions.map((execution) => (
                    <tr
                      key={execution.id}
                      className={`cursor-pointer ${
                        selected?.id === execution.id ? "bg-brand/5" : ""
                      }`}
                      onClick={() => setSelected(execution)}
                    >
                      <td className="font-mono text-xs">{execution.tool_name}</td>
                      <td>
                        <StatusBadge status={execution.status} />
                      </td>
                      <td className="max-w-[220px] truncate font-mono text-xs text-ink-muted">
                        {execution.policy_rule_id || "—"}
                      </td>
                      <td className="tabular-nums text-xs">
                        {formatDuration(execution.duration_ms)}
                      </td>
                      <td className="whitespace-nowrap text-xs text-ink-muted">
                        {formatTimestamp(execution.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card
            title={selected ? selected.tool_name : "Execution detail"}
            subtitle={selected ? selected.trace_id : "Select an execution"}
            bodyClassName="p-5 space-y-4"
          >
            {!selected ? (
              <EmptyState title="Nothing selected" />
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  <StatusBadge status={selected.status} />
                  <StatusBadge status={selected.decision} />
                  {selected.sandbox_id && <Badge tone="brand">{selected.sandbox_backend}</Badge>}
                  {selected.timed_out && <Badge tone="danger">timed out</Badge>}
                  {selected.truncated && <Badge tone="warn">truncated</Badge>}
                </div>
                {selected.reason && (
                  <div>
                    <p className="label">Decision reason</p>
                    <p className="text-sm">{selected.reason}</p>
                  </div>
                )}
                <div>
                  <p className="label">Normalised arguments</p>
                  <pre className="code-block max-h-40 overflow-auto">
                    {JSON.stringify(selected.arguments, null, 2)}
                  </pre>
                </div>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <p className="label">Exit code</p>
                    <p className="font-mono text-xs">{selected.exit_code}</p>
                  </div>
                  <div>
                    <p className="label">Duration</p>
                    <p className="font-mono text-xs">
                      {formatDuration(selected.duration_ms)}
                    </p>
                  </div>
                  <div>
                    <p className="label">Output size</p>
                    <p className="font-mono text-xs">{selected.output_bytes} B</p>
                  </div>
                  <div>
                    <p className="label">Sandbox</p>
                    <p className="truncate font-mono text-xs">
                      {selected.sandbox_id || "not used"}
                    </p>
                  </div>
                </div>
                {selected.error && (
                  <div>
                    <p className="label">Error</p>
                    <pre className="code-block whitespace-pre-wrap text-danger">
                      {selected.error}
                    </pre>
                  </div>
                )}
                {selected.output && (
                  <div>
                    <p className="label">Output</p>
                    <pre className="code-block max-h-80 overflow-auto whitespace-pre-wrap">
                      {selected.output}
                    </pre>
                  </div>
                )}
              </>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
