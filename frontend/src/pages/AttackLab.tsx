import { useState } from "react";
import { api } from "../api/client";
import type { LabRun, LabScenario, LabStatistics } from "../api/client";
import { useApi, formatDuration, formatTimestamp } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, Stat, StatusBadge } from "../components/ui";

export function AttackLabPage() {
  const catalogue = useApi<{ scenarios: LabScenario[]; count: number; categories: string[] }>(
    (signal) => api.get("/attack-lab/scenarios", signal),
    [],
  );
  const runs = useApi<{ runs: LabRun[]; statistics: LabStatistics }>(
    (signal) => api.get("/attack-lab/runs?limit=200", signal),
    [],
  );
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const scenario = catalogue.data?.scenarios.find((item) => item.id === selected) ?? null;
  const statistics = runs.data?.statistics;

  async function run(scenarioId: string) {
    setBusy(scenarioId);
    setError(null);
    try {
      await api.post(`/attack-lab/run/${scenarioId}`);
      runs.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(null);
    }
  }

  async function runAll() {
    setBusy("all");
    setError(null);
    try {
      await api.post("/attack-lab/run-all");
      runs.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Prompt-injection security laboratory</h1>
          <p className="text-sm text-ink-muted">
            Realistic attack scenarios replayed through the real policy engine, the real hard
            guards and the real sandbox. Nothing is mocked.
          </p>
        </div>
        <button type="button" className="btn-primary" onClick={() => void runAll()} disabled={busy === "all"}>
          {busy === "all" ? "Running the catalogue…" : "Run the whole catalogue"}
        </button>
      </header>

      {error && <ErrorState message={error} />}

      {statistics && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Stat
            label="Attack success rate"
            value={`${(statistics.attack_success_rate * 100).toFixed(1)}%`}
            tone={statistics.attack_success_rate === 0 ? "ok" : "danger"}
            hint={`${statistics.malicious_blocked}/${statistics.malicious_total} attacks blocked`}
          />
          <Stat
            label="False positive rate"
            value={`${(statistics.false_positive_rate * 100).toFixed(1)}%`}
            tone={statistics.false_positive_rate === 0 ? "ok" : "warn"}
            hint={`${statistics.benign_allowed}/${statistics.benign_total} benign workflows allowed`}
          />
          <Stat label="Denials" value={statistics.deny_count} tone="danger" hint="Actions refused by policy" />
          <Stat
            label="Approvals required"
            value={statistics.approval_count}
            tone="warn"
            hint="Actions parked for a human"
          />
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <Card
          title={`Scenarios (${catalogue.data?.count ?? 0})`}
          subtitle="Malicious and benign cases side by side"
          bodyClassName="p-0"
        >
          {catalogue.loading ? (
            <Spinner />
          ) : catalogue.error ? (
            <div className="p-4">
              <ErrorState message={catalogue.error} onRetry={catalogue.reload} />
            </div>
          ) : (
            <ul className="max-h-[720px] divide-y divide-edge overflow-y-auto">
              {catalogue.data?.scenarios.map((item) => {
                const lastRun = runs.data?.runs.find((runItem) => runItem.scenario_id === item.id);
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      onClick={() => setSelected(item.id)}
                      className={`w-full px-5 py-3 text-left transition-colors ${
                        selected === item.id ? "bg-brand/5" : "hover:bg-surface-sunken"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-ink-muted">{item.id}</span>
                        <StatusBadge status={item.expectation} />
                        <StatusBadge status={item.severity} />
                        {lastRun && (
                          <Badge tone={lastRun.passed ? "ok" : "danger"}>
                            {lastRun.passed ? "passed" : "failed"}
                          </Badge>
                        )}
                        <span className="ml-auto text-[11px] uppercase tracking-wide text-ink-faint">
                          {item.category}
                        </span>
                      </div>
                      <p className="mt-1 text-sm">{item.title}</p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <div className="space-y-6">
          {scenario && (
            <Card
              title={scenario.title}
              subtitle={scenario.id}
              actions={
                <button
                  type="button"
                  className="btn-primary btn-sm"
                  onClick={() => void run(scenario.id)}
                  disabled={busy === scenario.id}
                >
                  {busy === scenario.id ? "Running…" : "Run scenario"}
                </button>
              }
              bodyClassName="p-5 space-y-4"
            >
              <div className="flex flex-wrap gap-2">
                <StatusBadge status={scenario.expectation} />
                <StatusBadge status={scenario.severity} />
                <Badge tone="neutral">{scenario.category}</Badge>
              </div>
              <div>
                <p className="label">Attack input</p>
                <p className="text-sm text-ink-muted">{scenario.attack_input}</p>
              </div>
              {scenario.source_document && (
                <div>
                  <p className="label">Source document</p>
                  <p className="font-mono text-xs">{scenario.source_document}</p>
                </div>
              )}
              <div>
                <p className="label">Expected outcome</p>
                <p className="text-sm">{scenario.expected}</p>
              </div>
              <div>
                <p className="label">Proposed tool calls</p>
                <ol className="space-y-2">
                  {scenario.steps.map((step, index) => (
                    <li key={`${step.tool}-${index}`} className="code-block">
                      {index + 1}. {step.tool}({JSON.stringify(step.arguments)}) → expect {step.expectation}
                    </li>
                  ))}
                </ol>
              </div>
            </Card>
          )}

          <Card title="Recent runs" bodyClassName="p-0">
            {runs.loading ? (
              <Spinner />
            ) : !runs.data || runs.data.runs.length === 0 ? (
              <EmptyState
                title="No runs recorded yet"
                description="Run a scenario or the whole catalogue to collect evidence."
              />
            ) : (
              <div className="table-wrap max-h-[520px] overflow-y-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Scenario</th>
                      <th scope="col">Result</th>
                      <th scope="col">Observed</th>
                      <th scope="col">Duration</th>
                      <th scope="col">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.data.runs.map((run) => (
                      <tr key={run.id}>
                        <td className="font-mono text-xs">{run.scenario_id}</td>
                        <td>
                          <Badge tone={run.passed ? "ok" : "danger"}>
                            {run.passed ? "passed" : "failed"}
                          </Badge>
                        </td>
                        <td className="max-w-[220px] truncate text-xs text-ink-muted">
                          {run.observed_outcome}
                        </td>
                        <td className="tabular-nums text-xs">{formatDuration(run.duration_ms)}</td>
                        <td className="whitespace-nowrap text-xs text-ink-muted">
                          {formatTimestamp(run.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {runs.data && runs.data.runs.length > 0 && (
            <Card title="Latest run detail" bodyClassName="p-5 space-y-4">
              {(() => {
                const run = runs.data.runs[0];
                return (
                  <>
                    <div className="flex flex-wrap gap-2">
                      <span className="font-mono text-xs">{run.scenario_id}</span>
                      <Badge tone={run.passed ? "ok" : "danger"}>
                        {run.passed ? "passed" : "failed"}
                      </Badge>
                      <Badge tone="neutral">trace {run.trace_id.slice(0, 12)}</Badge>
                    </div>
                    {run.notes && <p className="text-sm text-warn">{run.notes}</p>}
                    <div>
                      <p className="label">Policy decision</p>
                      <pre className="code-block max-h-48 overflow-auto">
                        {JSON.stringify(run.policy_decision, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <p className="label">Execution result</p>
                      <pre className="code-block max-h-48 overflow-auto">
                        {JSON.stringify(run.execution_result.steps, null, 2)}
                      </pre>
                    </div>
                  </>
                );
              })()}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
