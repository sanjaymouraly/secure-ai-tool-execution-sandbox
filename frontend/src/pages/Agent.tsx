import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { AgentExecution, AgentMessage, AgentRunResult, AgentSessionSummary } from "../api/client";
import { useApi, formatDuration, formatTimestamp, formatUsd } from "../hooks/useApi";
import { Badge, Card, EmptyState, ErrorState, Spinner, StatusBadge } from "../components/ui";

interface SessionDetail {
  session: AgentSessionSummary;
  messages: AgentMessage[];
  executions: AgentExecution[];
}

export function AgentPage() {
  const sessions = useApi<{ sessions: AgentSessionSummary[] }>(
    (signal) => api.get("/sessions", signal),
    [],
  );
  const [activeId, setActiveId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [message, setMessage] = useState("");
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<AgentRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const traceEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!activeId && sessions.data && sessions.data.sessions.length > 0) {
      setActiveId(sessions.data.sessions[0].id);
    }
  }, [sessions.data, activeId]);

  const loadDetail = useCallback(async (sessionId: string) => {
    const data = await api.get<SessionDetail>(`/sessions/${sessionId}`);
    setDetail(data);
  }, []);

  useEffect(() => {
    if (activeId) {
      void loadDetail(activeId).catch((caught: unknown) =>
        setError(caught instanceof Error ? caught.message : String(caught)),
      );
    }
  }, [activeId, loadDetail]);

  useEffect(() => {
    traceEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [detail, runResult]);

  async function createSession() {
    setError(null);
    try {
      const created = await api.post<AgentSessionSummary>("/sessions", {
        title: `Session ${new Date().toLocaleTimeString()}`,
      });
      setActiveId(created.id);
      setDetail(null);
      setRunResult(null);
      sessions.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  async function send() {
    if (!activeId || !message.trim()) return;
    setRunning(true);
    setError(null);
    setRunResult(null);
    try {
      const result = await api.post<AgentRunResult>(`/sessions/${activeId}/run`, {
        message,
      });
      setRunResult(result);
      setMessage("");
      await loadDetail(activeId);
      sessions.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
      <div className="space-y-4">
        <Card
          title="Sessions"
          actions={
            <button type="button" className="btn-primary btn-sm" onClick={() => void createSession()}>
              New
            </button>
          }
          bodyClassName="p-0"
        >
          {sessions.loading ? (
            <Spinner />
          ) : sessions.error ? (
            <div className="p-4">
              <ErrorState message={sessions.error} onRetry={sessions.reload} />
            </div>
          ) : !sessions.data || sessions.data.sessions.length === 0 ? (
            <EmptyState title="No sessions yet" description="Create a session to start an agent run." />
          ) : (
            <ul className="max-h-[520px] overflow-y-auto p-2">
              {sessions.data.sessions.map((session) => (
                <li key={session.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveId(session.id);
                      setRunResult(null);
                    }}
                    className={`mb-1 w-full rounded-lg px-3 py-2 text-left transition-colors ${
                      activeId === session.id
                        ? "bg-brand/10 text-brand"
                        : "text-ink-muted hover:bg-surface-sunken hover:text-ink"
                    }`}
                  >
                    <span className="block truncate text-sm font-medium">{session.title}</span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-faint">
                      <StatusBadge status={session.status} />
                      <span>{session.tool_calls} tools</span>
                      {session.blocked > 0 && <span className="text-danger">{session.blocked} blocked</span>}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {detail && (
          <Card title="Session detail" bodyClassName="p-5 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-ink-muted">Provider</span>
              <span className="font-mono text-xs">{detail.session.provider}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Model</span>
              <span className="truncate font-mono text-xs">{detail.session.model}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Steps</span>
              <span className="font-mono text-xs">{detail.session.steps}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Cost</span>
              <span className="font-mono text-xs">{formatUsd(detail.session.cost_usd)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Tokens</span>
              <span className="font-mono text-xs">{detail.session.tokens}</span>
            </div>
            <button
              type="button"
              className="btn-secondary btn-sm w-full"
              onClick={() =>
                void api
                  .post(`/sessions/${detail.session.id}/cancel`)
                  .then(() => sessions.reload())
                  .catch(() => undefined)
              }
            >
              Request cancellation
            </button>
          </Card>
        )}
      </div>

      <div className="space-y-6">
        <Card
          title="Agent console"
          subtitle="The model proposes tool calls. The policy engine decides whether they may run."
        >
          <form
            className="space-y-3"
            onSubmit={(event) => {
              event.preventDefault();
              void send();
            }}
          >
            <label className="label" htmlFor="agent-message">
              Request
            </label>
            <textarea
              id="agent-message"
              className="field min-h-[92px] font-mono text-xs"
              placeholder="Read documents/quarterly-report.md and summarise the latency improvements."
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              disabled={!activeId || running}
            />
            <div className="flex flex-wrap items-center gap-2">
              <button type="submit" className="btn-primary" disabled={!activeId || running || !message.trim()}>
                {running ? "Running…" : "Run agent"}
              </button>
              {!activeId && (
                <span className="text-xs text-ink-muted">Create a session to begin.</span>
              )}
              <span className="ml-auto text-xs text-ink-faint">
                The default provider is the deterministic offline planner, so the run works
                without any paid API.
              </span>
            </div>
          </form>

          {error && (
            <div className="mt-4">
              <ErrorState message={error} />
            </div>
          )}
        </Card>

        {runResult && (
          <Card
            title="Run result"
            subtitle={`${runResult.steps.length} step(s) · ${runResult.executions.length} tool call(s)`}
            actions={<StatusBadge status={runResult.status} />}
          >
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-4">
                <Metric label="Blocked" value={runResult.blocked} tone="danger" />
                <Metric label="Completed" value={runResult.approved} tone="ok" />
                <Metric label="Tokens" value={runResult.total_tokens} />
                <Metric label="Cost" value={formatUsd(runResult.total_cost_usd)} />
              </div>
              {runResult.final_text && (
                <div>
                  <p className="label">Final answer</p>
                  <div className="code-block whitespace-pre-wrap">{runResult.final_text}</div>
                </div>
              )}
              {runResult.error && (
                <p className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
                  {runResult.error}
                </p>
              )}
            </div>
          </Card>
        )}

        <Card
          title="Live execution trace"
          subtitle="Every message and tool decision of the selected session"
          bodyClassName="p-0"
          actions={
            detail ? (
              <Link to={`/executions?session=${detail.session.id}`} className="btn-secondary btn-sm">
                Open in executions
              </Link>
            ) : undefined
          }
        >
          {!detail ? (
            <EmptyState title="Select a session" description="Choose a session to inspect its trace." />
          ) : detail.messages.length === 0 ? (
            <EmptyState title="No messages yet" description="Send a request to start the agent loop." />
          ) : (
            <div className="max-h-[640px] space-y-3 overflow-y-auto p-5">
              {detail.messages.map((msg) => (
                <MessageBubble key={msg.id} message={msg} />
              ))}
              <div ref={traceEndRef} />
            </div>
          )}
        </Card>

        {detail && detail.executions.length > 0 && (
          <Card title="Policy decisions of this session" bodyClassName="p-0">
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Tool</th>
                    <th scope="col">Status</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.executions.map((execution) => (
                    <tr key={execution.id}>
                      <td className="font-mono text-xs">{execution.tool_name}</td>
                      <td>
                        <StatusBadge status={execution.status} />
                      </td>
                      <td className="font-mono text-xs text-ink-muted">
                        {execution.policy_rule_id || "—"}
                      </td>
                      <td className="max-w-md truncate text-xs text-ink-muted" title={execution.reason}>
                        {execution.reason || "—"}
                      </td>
                      <td className="tabular-nums text-xs">
                        {formatDuration(execution.duration_ms)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "ok" | "danger";
}) {
  const color = tone === "ok" ? "text-ok" : tone === "danger" ? "text-danger" : "text-ink";
  return (
    <div className="rounded-lg border border-edge bg-surface p-3">
      <p className="text-[11px] font-medium uppercase tracking-wide text-ink-faint">{label}</p>
      <p className={`mt-1 text-lg font-semibold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

function MessageBubble({ message }: { message: AgentMessage }) {
  const isUser = message.role === "user";
  const isTool = message.role === "tool";
  const alignment = isUser ? "ml-auto max-w-[85%]" : "mr-auto max-w-full";
  const bubble = isUser
    ? "bg-brand text-white"
    : isTool
      ? "border border-edge bg-surface-sunken text-ink"
      : "border border-edge bg-surface-raised text-ink";

  let body = message.content;
  try {
    const parsed = JSON.parse(message.content);
    if (parsed && typeof parsed === "object" && "result" in parsed) {
      body = String(parsed.result);
      if (parsed.reason) body = `${body}\n\n— ${parsed.reason}`;
    }
  } catch {
    /* plain text */
  }

  return (
    <div className={`flex flex-col ${alignment}`}>
      <div className="mb-1 flex items-center gap-2 text-[11px] uppercase tracking-wide text-ink-faint">
        <span>{message.role}</span>
        {message.is_untrusted && (
          <Badge tone="warn" title="Content returned by a tool is untrusted data">
            untrusted
          </Badge>
        )}
        {message.name && <span className="font-mono normal-case">{message.name}</span>}
        <span className="font-normal normal-case">{formatTimestamp(message.created_at)}</span>
      </div>
      <div className={`rounded-lg px-3.5 py-2.5 text-sm ${bubble}`}>
        {message.tool_calls && message.tool_calls.length > 0 && (
          <ul className="mb-2 space-y-1">
            {message.tool_calls.map((call) => (
              <li key={call.id} className="code-block">
                → {call.name}({JSON.stringify(call.arguments)})
              </li>
            ))}
          </ul>
        )}
        <p className="whitespace-pre-wrap break-words">{body}</p>
      </div>
    </div>
  );
}
