/**
 * Typed API client.
 *
 * The browser never stores a credential: the session lives in an HttpOnly
 * cookie and the CSRF token in a readable cookie that is echoed back in the
 * `X-CSRF-Token` header for every state changing request.
 */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

function readCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[2]) : "";
}

export function csrfToken(): string {
  return readCookie("sax_csrf");
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase())) {
    const token = csrfToken();
    if (token) headers["X-CSRF-Token"] = token;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    credentials: "include",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const detail =
      typeof payload === "string"
        ? payload
        : (payload?.detail ?? payload?.message ?? `Request failed with status ${response.status}`);
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return payload as T;
}

export const api = {
  get: <T,>(path: string, signal?: AbortSignal) => apiFetch<T>(path, { method: "GET", signal }),
  post: <T,>(path: string, body?: unknown) => apiFetch<T>(path, { method: "POST", body }),
  put: <T,>(path: string, body?: unknown) => apiFetch<T>(path, { method: "PUT", body }),
  del: <T,>(path: string) => apiFetch<T>(path, { method: "DELETE" }),
};

/**
 * Call an endpoint that lives at the service root rather than under the
 * versioned API prefix (`/health`, `/ready`, `/overview`, `/metrics`).
 */
export async function rootFetch<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "include",
    signal,
  });
  if (!response.ok) {
    throw new ApiError(response.status, `Request to ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

/* ------------------------------------------------------------------ types */

export interface ToolManifest {
  name: string;
  title: string;
  description: string;
  risk: string;
  category: string;
  requires_approval: boolean;
  mutates_state: boolean;
  version: string;
  parameters: Record<string, unknown>;
}

export interface PolicyDecision {
  allowed: boolean;
  effect: string;
  reason: string;
  rule_id: string;
  rule_description: string;
  policy_version: string;
  policy_revision: number;
  source: string;
  explanation: string[];
  matched_constraints: string[];
  requires_approval: boolean;
}

export interface BrokerResult {
  execution_id: string;
  trace_id: string;
  tool_name: string;
  status: string;
  decision: PolicyDecision;
  approval_required: boolean;
  approval_id: string | null;
  output: string;
  error: string | null;
  exit_code: number;
  duration_ms: number;
  sandbox_id: string;
  sandbox_backend: string;
  isolated: boolean;
  metadata: Record<string, unknown>;
}

export interface Approval {
  id: string;
  session_id: string | null;
  tool_name: string;
  arguments: Record<string, unknown>;
  argument_hash: string;
  reason: string;
  risk: string;
  status: string;
  scope: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  sequence: number;
  created_at: string;
  actor_id: string;
  actor_role: string;
  session_id: string | null;
  trace_id: string | null;
  action: string;
  tool_name: string;
  outcome: string;
  policy_version: string;
  policy_rule_id: string;
  target: string;
  arguments: Record<string, unknown>;
  result_summary: string;
  sandbox_id: string;
  approval_decision: string;
  approved_by: string | null;
  duration_ms: number;
  event_hash: string;
  previous_hash: string;
}

export interface Overview {
  generated_at: string;
  executions: {
    total: number;
    completed: number;
    denied: number;
    failed: number;
    awaiting_approval: number;
    timed_out: number;
    last_24h: number;
    by_tool: Record<string, number>;
    by_outcome: Record<string, number>;
  };
  audit: { total_events: number };
  usage: {
    total_cost_usd: number;
    total_tokens: number;
    session_budget_usd: number;
    daily_budget_usd: number;
  };
  policy: { version: string; revision: number; rules: number };
  provider: { default: string; model: string };
  recent_executions: Array<{
    id: string;
    tool_name: string;
    status: string;
    decision: string;
    reason: string;
    duration_ms: number;
    created_at: string;
    trace_id: string;
  }>;
}

export interface SandboxStatus {
  name: string;
  available: boolean;
  isolated: boolean;
  detail: string;
  image: string;
  rootless: boolean;
  apparmor: boolean;
  seccomp: boolean;
  user_namespaces: boolean;
  warnings: string[];
  version: string;
}

export interface ProviderType {
  id: string;
  label: string;
  format: string;
  default_base_url: string;
  requires_key: boolean;
  notes: string;
}

export interface ProviderProfile {
  id: string;
  name: string;
  provider_type: string;
  base_url: string;
  model: string;
  has_api_key: boolean;
  api_key_hint: string;
  extra_header_names: string[];
  options: Record<string, unknown>;
  timeout_seconds: number;
  max_retries: number;
  max_tokens: number;
  temperature: number;
  is_active: boolean;
  is_default: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string;
}

export interface AgentSessionSummary {
  id: string;
  title: string;
  status: string;
  provider: string;
  model: string;
  user_id: string;
  project_id: string | null;
  agent_id: string;
  steps: number;
  tool_calls: number;
  blocked: number;
  approved: number;
  cost_usd: number;
  tokens: number;
  cancelled: boolean;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentMessage {
  id: string;
  role: string;
  content: string;
  sequence: number;
  tool_calls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> | null;
  tool_call_id: string | null;
  name: string | null;
  is_untrusted: boolean;
  usage: Record<string, unknown> | null;
  created_at: string;
}

export interface AgentExecution {
  id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  status: string;
  decision: string;
  reason: string;
  policy_rule_id: string;
  policy_version: string;
  trace_id: string;
  exit_code: number;
  duration_ms: number;
  output: string;
  error: string | null;
  sandbox_id: string;
  sandbox_backend: string;
  timed_out: boolean;
  created_at: string;
}

export interface AgentRunResult {
  session_id: string;
  status: string;
  final_text: string;
  steps: Array<{
    index: number;
    provider: string;
    model: string;
    text: string;
    tool_calls: Array<{ id: string; name: string; arguments: Record<string, unknown> }>;
    usage: Record<string, unknown>;
    cost_usd: number;
    error: string;
    duration_ms: number;
  }>;
  executions: Array<{
    id: string;
    tool_name: string;
    status: string;
    decision: string;
    reason: string;
    trace_id: string;
    duration_ms: number;
    output: string;
    error: string | null;
  }>;
  total_cost_usd: number;
  total_tokens: number;
  blocked: number;
  approved: number;
  error: string;
}

export interface LabScenario {
  id: string;
  title: string;
  category: string;
  severity: string;
  expectation: string;
  expected: string;
  description: string;
  attack_input: string;
  source_document: string;
  steps: Array<{ tool: string; expectation: string; arguments: Record<string, unknown> }>;
}

export interface LabRun {
  id: string;
  scenario_id: string;
  title: string;
  category: string;
  severity: string;
  expectation: string;
  observed_outcome: string;
  passed: boolean;
  attack_input: string;
  proposed_tool_call: { steps: Array<{ tool: string; arguments: Record<string, unknown> }> };
  policy_decision: {
    steps: Array<{ decision: string; reason: string; rule_id: string; policy_version: string }>;
  };
  execution_result: {
    steps: Array<{
      index: number;
      tool: string;
      expected: string;
      observed: string;
      passed: boolean;
      status: string;
      decision: string;
      reason: string;
      rule_id: string;
      trace_id: string;
      duration_ms: number;
      output_preview: string;
    }>;
    protected_fixture_intact: boolean;
  };
  trace_id: string;
  duration_ms: number;
  notes: string;
  created_at: string;
}

export interface LabStatistics {
  total_runs: number;
  malicious_total: number;
  malicious_blocked: number;
  attack_success_rate: number;
  deny_count: number;
  approval_count: number;
  benign_total: number;
  benign_allowed: number;
  false_positive_count: number;
  false_positive_rate: number;
  by_category: Record<string, { total: number; blocked: number; passed: number }>;
}

export interface CurrentUser {
  id: string;
  username: string;
  email: string | null;
  role: string;
  is_superuser: boolean;
  is_active: boolean;
}
