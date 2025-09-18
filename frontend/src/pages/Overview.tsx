import { Link } from "react-router-dom";
import { rootFetch } from "../api/client";
import type { Overview } from "../api/client";
import { useApi, formatDuration, formatTimestamp, formatUsd } from "../hooks/useApi";
import { Card, EmptyState, ErrorState, ProgressBar, Spinner, Stat, StatusBadge } from "../components/ui";

export function OverviewPage() {
  const { data, loading, error, reload } = useApi<Overview>(
    (signal) => rootFetch<Overview>("/overview", signal),
    [],
  );

  if (loading) return <Spinner label="Loading metrics" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <EmptyState title="No overview data available" />;

  const executions = data.executions;
  const total = Math.max(executions.total, 1);
  const denyRate = executions.denied / total;
  const allowRate = executions.completed / total;

  const toolEntries = Object.entries(executions.by_tool).sort((a, b) => b[1] - a[1]);
  const maxToolCount = toolEntries.length ? toolEntries[0][1] : 1;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Security operations overview</h1>
          <p className="text-sm text-ink-muted">
            Live execution activity and authorisation outcomes, straight from the audit trail.
          </p>
        </div>
        <p className="text-xs text-ink-faint">Updated {formatTimestamp(data.generated_at)}</p>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Total executions"
          value={executions.total}
          hint={`${executions.last_24h} in the last 24 h`}
        />
        <Stat
          label="Completed"
          value={executions.completed}
          tone="ok"
          hint={`${Math.round(allowRate * 100)}% of all executions`}
        />
        <Stat
          label="Denied by policy"
          value={executions.denied}
          tone="danger"
          hint={`${Math.round(denyRate * 100)}% of all executions`}
        />
        <Stat
          label="Awaiting approval"
          value={executions.awaiting_approval}
          tone="warn"
          hint={`${executions.failed} failed · ${executions.timed_out} timed out`}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card
          title="Authorisation mix"
          subtitle="Outcome of every policy evaluation"
          className="lg:col-span-2"
          bodyClassName="p-5 space-y-4"
        >
          {executions.total === 0 ? (
            <EmptyState
              title="No executions yet"
              description="Run the agent or invoke a tool to populate the metrics."
              action={
                <Link to="/agent" className="btn-primary btn-sm">
                  Open the agent
                </Link>
              }
            />
          ) : (
            <>
              <div>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span className="text-ink-muted">Allowed</span>
                  <span className="font-medium tabular-nums text-ok">
                    {executions.completed} ({Math.round(allowRate * 100)}%)
                  </span>
                </div>
                <ProgressBar value={allowRate} tone="ok" />
              </div>
              <div>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span className="text-ink-muted">Denied</span>
                  <span className="font-medium tabular-nums text-danger">
                    {executions.denied} ({Math.round(denyRate * 100)}%)
                  </span>
                </div>
                <ProgressBar value={denyRate} tone="danger" />
              </div>
              <div>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span className="text-ink-muted">Awaiting approval</span>
                  <span className="font-medium tabular-nums text-warn">
                    {executions.awaiting_approval}
                  </span>
                </div>
                <ProgressBar
                  value={executions.awaiting_approval / total}
                  tone="warn"
                />
              </div>

              {toolEntries.length > 0 && (
                <div className="pt-2">
                  <p className="label">Tool usage</p>
                  <ul className="space-y-1.5">
                    {toolEntries.map(([tool, count]) => (
                      <li key={tool} className="flex items-center gap-3 text-xs">
                        <span className="w-44 shrink-0 truncate font-mono text-ink-muted">{tool}</span>
                        <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-sunken">
                          <span
                            className="block h-full rounded-full bg-brand"
                            style={{ width: `${(count / maxToolCount) * 100}%` }}
                          />
                        </span>
                        <span className="w-10 shrink-0 text-right tabular-nums">{count}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </Card>

        <div className="space-y-6">
          <Card title="Policy" bodyClassName="p-5 space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Version</span>
              <span className="font-mono text-sm">{data.policy.version}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Revision</span>
              <span className="font-mono text-sm">{data.policy.revision}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Active rules</span>
              <span className="font-mono text-sm">{data.policy.rules}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Default effect</span>
              <StatusBadge status="deny" />
            </div>
            <Link to="/policies" className="btn-secondary btn-sm w-full">
              Review the policy
            </Link>
          </Card>

          <Card title="Provider usage" bodyClassName="p-5 space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Provider</span>
              <span className="font-mono text-sm">{data.provider.default}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Model</span>
              <span className="truncate font-mono text-sm">{data.provider.model}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Estimated cost</span>
              <span className="font-mono text-sm">{formatUsd(data.usage.total_cost_usd)}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Tokens</span>
              <span className="font-mono text-sm">{data.usage.total_tokens.toLocaleString()}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Session budget</span>
              <span className="font-mono text-sm">{formatUsd(data.usage.session_budget_usd)}</span>
            </div>
            <Link to="/providers" className="btn-secondary btn-sm w-full">
              Configure the provider
            </Link>
          </Card>

          <Card title="Audit trail" bodyClassName="p-5 space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-muted">Recorded events</span>
              <span className="font-mono text-sm">{data.audit.total_events}</span>
            </div>
            <p className="text-xs text-ink-muted">
              Records are chained with HMAC-SHA256 so tampering is detectable.
            </p>
            <Link to="/audit" className="btn-secondary btn-sm w-full">
              Open the audit explorer
            </Link>
          </Card>
        </div>
      </div>

      <Card
        title="Recent executions"
        subtitle="The ten most recent tool invocations"
        bodyClassName="p-0"
        actions={
          <Link to="/executions" className="btn-secondary btn-sm">
            View all
          </Link>
        }
      >
        {data.recent_executions.length === 0 ? (
          <EmptyState title="Nothing has run yet" />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Status</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Duration</th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_executions.map((execution) => (
                  <tr key={execution.id}>
                    <td className="font-mono text-xs">{execution.tool_name}</td>
                    <td>
                      <StatusBadge status={execution.status} />
                    </td>
                    <td>
                      <StatusBadge status={execution.decision} />
                    </td>
                    <td className="max-w-md truncate text-xs text-ink-muted" title={execution.reason}>
                      {execution.reason || "—"}
                    </td>
                    <td className="tabular-nums text-xs">{formatDuration(execution.duration_ms)}</td>
                    <td className="text-xs text-ink-muted">
                      {formatTimestamp(execution.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
