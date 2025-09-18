import { useState } from "react";
import { api } from "../api/client";
import type { AuditEvent } from "../api/client";
import { useApi, formatTimestamp } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

interface AuditList {
  events: AuditEvent[];
  count: number;
  latest_sequence: number;
}

interface Verification {
  valid: boolean;
  records: number;
  broken: Array<{ sequence: number; reason: string }>;
  checked_at: string;
}

export function AuditPage() {
  const [outcome, setOutcome] = useState("");
  const [tool, setTool] = useState("");
  const [actor, setActor] = useState("");
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [exporting, setExporting] = useState(false);

  const query = new URLSearchParams();
  if (outcome) query.set("outcome", outcome);
  if (tool) query.set("tool_name", tool);
  if (actor) query.set("actor_id", actor);
  query.set("limit", "200");

  const events = useApi<AuditList>((signal) => api.get(`/audit/events?${query.toString()}`, signal), [
    outcome,
    tool,
    actor,
  ]);
  const verification = useApi<Verification>((signal) => api.get("/audit/verify", signal), []);

  async function exportAudit() {
    setExporting(true);
    try {
      const response = await fetch("/api/v1/audit/export?fmt=json&limit=2000", {
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Export failed with status ${response.status}`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `audit-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    } catch {
      /* the export requires administrator rights; the message is shown by the button state */
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Audit trail</h1>
          <p className="text-sm text-ink-muted">
            Append-only records with an HMAC-SHA256 integrity chain. Tampering is detectable with
            the verification endpoint.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {verification.data && (
            <Badge tone={verification.data.valid ? "ok" : "danger"}>
              chain {verification.data.valid ? "intact" : "broken"}
            </Badge>
          )}
          <button type="button" className="btn-secondary" onClick={() => void exportAudit()} disabled={exporting}>
            {exporting ? "Exporting…" : "Export JSON"}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              verification.reload();
              events.reload();
            }}
          >
            Verify chain
          </button>
        </div>
      </header>

      {verification.data && !verification.data.valid && (
        <div className="rounded-lg border border-danger/30 bg-danger/5 p-4">
          <p className="text-sm font-semibold text-danger">The integrity chain is broken</p>
          <ul className="mt-1.5 space-y-1 font-mono text-xs text-ink-muted">
            {verification.data.broken.map((item) => (
              <li key={`${item.sequence}-${item.reason}`}>
                sequence {item.sequence}: {item.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      <Card title="Filters" bodyClassName="p-5">
        <div className="grid gap-3 sm:grid-cols-4">
          <div>
            <label className="label" htmlFor="audit-outcome">
              Outcome
            </label>
            <select
              id="audit-outcome"
              className="field"
              value={outcome}
              onChange={(event) => setOutcome(event.target.value)}
            >
              <option value="">all</option>
              <option value="completed">completed</option>
              <option value="denied">denied</option>
              <option value="failed">failed</option>
              <option value="awaiting_approval">awaiting_approval</option>
              <option value="allowed">allowed</option>
            </select>
          </div>
          <div>
            <label className="label" htmlFor="audit-tool">
              Tool
            </label>
            <input
              id="audit-tool"
              className="field font-mono text-xs"
              placeholder="read_file"
              value={tool}
              onChange={(event) => setTool(event.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="audit-actor">
              Actor id
            </label>
            <input
              id="audit-actor"
              className="field font-mono text-xs"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
            />
          </div>
          <div className="flex items-end">
            <button type="button" className="btn-secondary" onClick={events.reload}>
              Refresh
            </button>
          </div>
        </div>
      </Card>

      {events.loading ? (
        <Spinner label="Loading the audit trail" />
      ) : events.error ? (
        <ErrorState message={events.error} onRetry={events.reload} />
      ) : (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <Card title={`Events (${events.data?.count ?? 0})`} bodyClassName="p-0">
            {!events.data || events.data.events.length === 0 ? (
              <EmptyState title="No audit events match these filters" />
            ) : (
              <div className="table-wrap max-h-[720px] overflow-y-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">#</th>
                      <th scope="col">Action</th>
                      <th scope="col">Outcome</th>
                      <th scope="col">Actor</th>
                      <th scope="col">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.data.events.map((event) => (
                      <tr
                        key={event.id}
                        className={`cursor-pointer ${selected?.id === event.id ? "bg-brand/5" : ""}`}
                        onClick={() => setSelected(event)}
                      >
                        <td className="tabular-nums text-xs text-ink-faint">{event.sequence}</td>
                        <td className="font-mono text-xs">{event.action}</td>
                        <td>
                          <StatusBadge status={event.outcome} />
                        </td>
                        <td className="max-w-[140px] truncate font-mono text-xs text-ink-muted">
                          {event.actor_id}
                        </td>
                        <td className="whitespace-nowrap text-xs text-ink-muted">
                          {formatTimestamp(event.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Event detail" subtitle="Chain proof" bodyClassName="p-5 space-y-4">
            {!selected ? (
              <EmptyState title="Select an event" />
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  <StatusBadge status={selected.outcome} />
                  <Badge tone="neutral">seq {selected.sequence}</Badge>
                  {selected.approval_decision && (
                    <Badge tone="warn">{selected.approval_decision}</Badge>
                  )}
                </div>
                <div>
                  <p className="label">Action</p>
                  <p className="font-mono text-xs">{selected.action}</p>
                </div>
                {selected.result_summary && (
                  <div>
                    <p className="label">Summary</p>
                    <p className="text-sm text-ink-muted">{selected.result_summary}</p>
                  </div>
                )}
                <div>
                  <p className="label">Normalised arguments (redacted)</p>
                  <pre className="code-block max-h-48 overflow-auto">
                    {JSON.stringify(selected.arguments, null, 2)}
                  </pre>
                </div>
                <div>
                  <p className="label">Integrity</p>
                  <dl className="space-y-1.5 text-xs">
                    <div>
                      <dt className="text-ink-faint">Event hash</dt>
                      <dd className="break-all font-mono text-[11px]">{selected.event_hash}</dd>
                    </div>
                    <div>
                      <dt className="text-ink-faint">Previous hash</dt>
                      <dd className="break-all font-mono text-[11px]">
                        {selected.previous_hash || "(first record)"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-ink-faint">Policy</dt>
                      <dd className="font-mono text-[11px]">
                        {selected.policy_version} · {selected.policy_rule_id || "—"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-ink-faint">Trace</dt>
                      <dd className="font-mono text-[11px]">{selected.trace_id ?? "—"}</dd>
                    </div>
                  </dl>
                </div>
              </>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
