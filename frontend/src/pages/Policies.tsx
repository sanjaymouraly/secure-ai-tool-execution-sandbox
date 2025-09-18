import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  effect: string;
  priority: number;
  enabled: boolean;
  tools: string[];
  reason: string;
  requires_approval: boolean;
  constraints: Record<string, unknown>;
  subjects: Record<string, unknown>;
}

interface PolicyResponse {
  version: string;
  revision: number;
  name: string;
  description: string;
  defaults: { effect: string; reason: string };
  rules: PolicyRule[];
  tool_risk: Record<string, string>;
  content: Record<string, unknown>;
}

export function PoliciesPage() {
  const { permissions } = useAuth();
  const policy = useApi<PolicyResponse>((signal) => api.get("/policies/current", signal), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = useMemo(
    () => policy.data?.rules.find((rule) => rule.id === selectedId) ?? null,
    [policy.data, selectedId],
  );

  useEffect(() => {
    if (!selectedId && policy.data && policy.data.rules.length > 0) {
      setSelectedId(policy.data.rules[0].id);
    }
  }, [policy.data, selectedId]);

  async function reload() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api.post("/policies/reload");
      setMessage("The policy document was re-read from disk.");
      policy.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  if (policy.loading) return <Spinner label="Loading the policy" />;
  if (policy.error) return <ErrorState message={policy.error} onRetry={policy.reload} />;
  if (!policy.data) return <EmptyState title="No policy loaded" />;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Permission policy</h1>
          <p className="text-sm text-ink-muted">
            Version {policy.data.version} · revision {policy.data.revision} ·{" "}
            {policy.data.rules.length} rules, evaluated by descending priority.
          </p>
        </div>
        {permissions.can_edit_policy && (
          <button type="button" className="btn-secondary" onClick={() => void reload()} disabled={busy}>
            {busy ? "Reloading…" : "Reload from disk"}
          </button>
        )}
      </header>

      {message && (
        <p className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-sm text-ok">{message}</p>
      )}
      {error && <ErrorState message={error} />}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <Card
          title="Rules in evaluation order"
          subtitle="The first matching rule decides. The document default applies when nothing matches."
          bodyClassName="p-0"
        >
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Effect</th>
                  <th scope="col">Tools</th>
                </tr>
              </thead>
              <tbody>
                {policy.data.rules.map((rule) => (
                  <tr
                    key={rule.id}
                    onClick={() => setSelectedId(rule.id)}
                    className={`cursor-pointer ${selectedId === rule.id ? "bg-brand/5" : ""}`}
                  >
                    <td className="tabular-nums text-xs">{rule.priority}</td>
                    <td>
                      <span className="block font-mono text-xs">{rule.id}</span>
                      <span className="block text-xs text-ink-muted">{rule.description}</span>
                    </td>
                    <td>
                      <StatusBadge status={rule.effect} />
                    </td>
                    <td className="font-mono text-xs text-ink-muted">
                      {rule.tools.join(", ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="space-y-6">
          <Card title="Document defaults" bodyClassName="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-ink-muted">Default effect</span>
              <StatusBadge status={policy.data.defaults.effect} />
            </div>
            <p className="text-xs text-ink-muted">{policy.data.defaults.reason}</p>
            <p className="text-xs text-ink-faint">
              The hard guards in the code (path escapes, shell metacharacters, network access,
              oversized arguments) always run before these rules and can never be relaxed by a
              policy change.
            </p>
          </Card>

          {selected && (
            <Card title={selected.id} subtitle={selected.name} bodyClassName="p-5 space-y-4">
              <div className="flex flex-wrap gap-2">
                <StatusBadge status={selected.effect} />
                <Badge tone="neutral">priority {selected.priority}</Badge>
                {selected.requires_approval && <Badge tone="warn">approval</Badge>}
                {selected.enabled ? (
                  <Badge tone="ok">enabled</Badge>
                ) : (
                  <Badge tone="neutral">disabled</Badge>
                )}
              </div>
              <p className="text-sm text-ink-muted">{selected.description}</p>
              {selected.reason && (
                <div>
                  <p className="label">Reason returned to the operator</p>
                  <p className="text-sm">{selected.reason}</p>
                </div>
              )}
              <div>
                <p className="label">Tools</p>
                <div className="flex flex-wrap gap-1.5">
                  {selected.tools.map((tool) => (
                    <Badge key={tool} tone="brand">
                      {tool}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <p className="label">Subjects</p>
                <pre className="code-block max-h-40 overflow-auto">
                  {JSON.stringify(selected.subjects, null, 2)}
                </pre>
              </div>
              <div>
                <p className="label">Constraints</p>
                <pre className="code-block max-h-56 overflow-auto">
                  {JSON.stringify(selected.constraints, null, 2)}
                </pre>
              </div>
            </Card>
          )}

          <Card title="Tool risk register" bodyClassName="p-5">
            <ul className="space-y-1.5">
              {Object.entries(policy.data.tool_risk).map(([tool, risk]) => (
                <li key={tool} className="flex items-center justify-between text-sm">
                  <span className="font-mono text-xs">{tool}</span>
                  <StatusBadge status={risk} />
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
