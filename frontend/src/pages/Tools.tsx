import { useState } from "react";
import { api } from "../api/client";
import type { ToolManifest } from "../api/client";
import { useApi } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

export function ToolsPage() {
  const { data, loading, error, reload } = useApi<{ tools: ToolManifest[] }>(
    (signal) => api.get("/tools", signal),
    [],
  );
  const [active, setActive] = useState<string | null>(null);
  const [arguments_, setArguments] = useState("{\n  \"path\": \"documents/quarterly-report.md\"\n}");
  const [result, setResult] = useState<string | null>(null);
  const [invokeError, setInvokeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = data?.tools.find((tool) => tool.name === active) ?? data?.tools[0] ?? null;

  async function invoke() {
    if (!selected) return;
    setBusy(true);
    setInvokeError(null);
    setResult(null);
    try {
      const parsed = JSON.parse(arguments_ || "{}");
      const response = await api.post<Record<string, unknown>>(
        `/tools/${selected.name}/invoke`,
        { arguments: parsed },
      );
      setResult(JSON.stringify(response, null, 2));
    } catch (caught) {
      setInvokeError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Spinner label="Loading the tool registry" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Tool registry</h1>
        <p className="text-sm text-ink-muted">
          Every tool the agent may call. The JSON schema is shared between the model and the
          server, so an argument the schema rejects can never reach a handler.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card title="Registered tools" bodyClassName="p-0">
          <ul className="divide-y divide-edge">
            {data?.tools.map((tool) => (
              <li key={tool.name}>
                <button
                  type="button"
                  onClick={() => {
                    setActive(tool.name);
                    setResult(null);
                    setInvokeError(null);
                  }}
                  className={`w-full px-5 py-3 text-left transition-colors ${
                    selected?.name === tool.name
                      ? "bg-brand/5"
                      : "hover:bg-surface-sunken"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-medium">{tool.name}</span>
                    <StatusBadge status={tool.risk} />
                    {tool.requires_approval && <Badge tone="warn">approval required</Badge>}
                    {tool.mutates_state && <Badge tone="info">mutates state</Badge>}
                    <span className="ml-auto text-[11px] uppercase tracking-wide text-ink-faint">
                      {tool.category}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-ink-muted">{tool.description}</p>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <div className="space-y-6">
          {selected && (
            <Card title={selected.title} subtitle={selected.name} bodyClassName="p-5 space-y-4">
              <div className="flex flex-wrap gap-2">
                <Badge tone="brand">v{selected.version}</Badge>
                <StatusBadge status={selected.risk} />
                {selected.requires_approval && <Badge tone="warn">human approval</Badge>}
              </div>
              <p className="text-sm text-ink-muted">{selected.description}</p>
              <div>
                <p className="label">Parameter schema</p>
                <pre className="code-block max-h-72 overflow-y-auto">
                  {JSON.stringify(selected.parameters, null, 2)}
                </pre>
              </div>
            </Card>
          )}

          <Card
            title="Invoke"
            subtitle="Direct tool calls use exactly the same broker, policy engine and sandbox as the agent."
            bodyClassName="p-5 space-y-3"
          >
            <div>
              <label className="label" htmlFor="tool-args">
                Arguments (JSON)
              </label>
              <textarea
                id="tool-args"
                className="field min-h-[140px] font-mono text-xs"
                value={arguments_}
                onChange={(event) => setArguments(event.target.value)}
              />
            </div>
            <button
              type="button"
              className="btn-primary"
              onClick={() => void invoke()}
              disabled={busy || !selected}
            >
              {busy ? "Invoking…" : `Invoke ${selected?.name ?? "tool"}`}
            </button>
            {invokeError && <ErrorState message={invokeError} />}
            {result && (
              <div>
                <p className="label">Result</p>
                <pre className="code-block max-h-80 overflow-auto">{result}</pre>
              </div>
            )}
          </Card>
        </div>
      </div>

      {!data?.tools.length && <EmptyState title="No tools registered" />}
    </div>
  );
}
