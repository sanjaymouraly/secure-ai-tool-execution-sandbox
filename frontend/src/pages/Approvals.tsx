import { useState } from "react";
import { api } from "../api/client";
import type { Approval } from "../api/client";
import { useApi, formatTimestamp, relativeTime } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

export function ApprovalsPage() {
  const { permissions } = useAuth();
  const approvals = useApi<{ approvals: Approval[] }>(
    (signal) => api.get("/approvals?limit=200", signal),
    [],
  );
  const [note, setNote] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  async function decide(approval: Approval, decision: string) {
    setBusy(approval.id);
    setError(null);
    setFlash(null);
    try {
      await api.post(`/approvals/${approval.id}/decision`, {
        decision,
        note: note[approval.id] ?? "",
      });
      setFlash(
        decision === "deny"
          ? "The request was denied. The action will not run."
          : decision === "allow_once"
            ? "Approved once. The exact reviewed action may run."
            : "Approved for this session. The exact reviewed action may run again in this session.",
      );
      approvals.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(null);
    }
  }

  const pending = approvals.data?.approvals.filter((a) => a.status === "pending") ?? [];
  const decided = approvals.data?.approvals.filter((a) => a.status !== "pending") ?? [];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Human approval queue</h1>
        <p className="text-sm text-ink-muted">
          An approval authorises exactly one reviewed action. It is bound to a hash of the tool
          name and arguments, so changing a single argument invalidates it.
        </p>
      </header>

      {flash && (
        <p className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-sm text-ok">{flash}</p>
      )}
      {error && <ErrorState message={error} />}

      {approvals.loading ? (
        <Spinner label="Loading approvals" />
      ) : approvals.error ? (
        <ErrorState message={approvals.error} onRetry={approvals.reload} />
      ) : (
        <>
          <Card
            title={`Pending (${pending.length})`}
            subtitle="Actions that are waiting for a human decision"
            bodyClassName="p-0"
          >
            {pending.length === 0 ? (
              <EmptyState
                title="Nothing is waiting for approval"
                description="Sensitive actions appear here the moment the agent proposes them."
              />
            ) : (
              <ul className="divide-y divide-edge">
                {pending.map((approval) => (
                  <li key={approval.id} className="p-5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-medium">{approval.tool_name}</span>
                      <StatusBadge status={approval.risk} />
                      <Badge tone="warn">{approval.scope}</Badge>
                      <span className="ml-auto text-xs text-ink-faint">
                        requested {relativeTime(approval.created_at)}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm text-ink-muted">{approval.reason}</p>
                    <div className="mt-3">
                      <p className="label">Exact arguments under review</p>
                      <pre className="code-block max-h-40 overflow-auto">
                        {JSON.stringify(approval.arguments, null, 2)}
                      </pre>
                    </div>
                    <p className="mt-2 font-mono text-[11px] text-ink-faint">
                      signature {approval.argument_hash.slice(0, 24)}… · expires{" "}
                      {formatTimestamp(approval.expires_at)}
                    </p>
                    {permissions.can_approve ? (
                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        <input
                          className="field max-w-xs text-xs"
                          placeholder="Decision note (optional)"
                          value={note[approval.id] ?? ""}
                          onChange={(event) =>
                            setNote((current) => ({ ...current, [approval.id]: event.target.value }))
                          }
                          aria-label={`Decision note for ${approval.tool_name}`}
                        />
                        <button
                          type="button"
                          className="btn-primary btn-sm"
                          disabled={busy === approval.id}
                          onClick={() => void decide(approval, "allow_once")}
                        >
                          Allow once
                        </button>
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          disabled={busy === approval.id}
                          onClick={() => void decide(approval, "allow_for_session")}
                        >
                          Allow for session
                        </button>
                        <button
                          type="button"
                          className="btn-danger btn-sm"
                          disabled={busy === approval.id}
                          onClick={() => void decide(approval, "deny")}
                        >
                          Deny
                        </button>
                      </div>
                    ) : (
                      <p className="mt-3 text-xs text-ink-faint">
                        Your role cannot decide approvals. An approver or administrator must act.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={`Decision history (${decided.length})`} bodyClassName="p-0">
            {decided.length === 0 ? (
              <EmptyState title="No decisions yet" />
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Tool</th>
                      <th scope="col">Status</th>
                      <th scope="col">Decided by</th>
                      <th scope="col">When</th>
                      <th scope="col">Note</th>
                    </tr>
                  </thead>
                  <tbody>
                    {decided.map((approval) => (
                      <tr key={approval.id}>
                        <td className="font-mono text-xs">{approval.tool_name}</td>
                        <td>
                          <StatusBadge status={approval.status} />
                        </td>
                        <td className="font-mono text-xs text-ink-muted">
                          {approval.decided_by ?? "—"}
                        </td>
                        <td className="text-xs text-ink-muted">
                          {formatTimestamp(approval.decided_at)}
                        </td>
                        <td className="max-w-sm truncate text-xs text-ink-muted">
                          {approval.decision_note ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
