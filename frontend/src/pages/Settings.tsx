import { useState } from "react";
import { api, rootFetch } from "../api/client";
import { useApi, formatTimestamp } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";
import { Badge, Card, ErrorState, KeyValue, Spinner, StatusBadge } from "../components/ui";

interface SystemInfo {
  name: string;
  version: string;
  environment: string;
  python: string;
  platform: string;
  auth_mode: string;
  sandbox_backend: string;
  workspace_root: string;
  uptime_seconds: number;
  api_prefix: string;
}

interface Health {
  status: string;
  timestamp: string;
  service: string;
  version: string;
  uptime_seconds: number;
}

interface Ready {
  status: string;
  database: string;
  policy_version: string;
  timestamp: string;
}

export function SettingsPage() {
  const { user, authMode } = useAuth();
  const health = useApi<Health>((signal) => rootFetch<Health>("/health", signal), []);
  const ready = useApi<Ready>((signal) => rootFetch<Ready>("/ready", signal), []);
  const info = useApi<SystemInfo>((signal) => rootFetch<SystemInfo>("/system/info", signal), []);
  const [password, setPassword] = useState("");
  const [current, setCurrent] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function changePassword() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api.post("/auth/change-password", {
        current_password: current,
        new_password: password,
      });
      setMessage("The password was updated.");
      setCurrent("");
      setPassword("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Settings &amp; system health</h1>
        <p className="text-sm text-ink-muted">
          Runtime status of the control plane, the policy engine and the sandbox backend.
        </p>
      </header>

      {message && (
        <p className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-sm text-ok">{message}</p>
      )}
      {error && <ErrorState message={error} />}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Health" bodyClassName="p-5 space-y-4">
          {health.loading ? (
            <Spinner />
          ) : health.data ? (
            <>
              <div className="flex flex-wrap gap-2">
                <StatusBadge status={health.data.status} />
                {ready.data && <StatusBadge status={ready.data.status} />}
                <Badge tone={ready.data?.database === "ok" ? "ok" : "danger"}>
                  database {ready.data?.database ?? "unknown"}
                </Badge>
              </div>
              <KeyValue
                items={[
                  ["Service", health.data.service],
                  ["Version", health.data.version],
                  ["Checked at", formatTimestamp(health.data.timestamp)],
                  ["Uptime", `${Math.round(health.data.uptime_seconds)} s`],
                  ["Policy version", ready.data?.policy_version ?? "—"],
                ]}
              />
            </>
          ) : (
            <ErrorState message="The health endpoint did not answer." onRetry={health.reload} />
          )}
        </Card>

        <Card title="Deployment" bodyClassName="p-5">
          {info.loading ? (
            <Spinner />
          ) : info.data ? (
            <KeyValue
              items={[
                ["Environment", info.data.environment],
                ["Python", info.data.python],
                ["Platform", info.data.platform],
                ["Auth mode", info.data.auth_mode],
                ["Configured sandbox", info.data.sandbox_backend],
                ["Approved workspace", info.data.workspace_root],
                ["API prefix", info.data.api_prefix],
              ]}
            />
          ) : null}
        </Card>

        <Card title="Your account" bodyClassName="p-5 space-y-4">
          <KeyValue
            items={[
              ["Username", user?.username ?? "—"],
              ["Role", user?.role ?? "—"],
              ["Superuser", user?.is_superuser ? "yes" : "no"],
              ["Session mode", authMode],
            ]}
          />
          <div className="space-y-3 border-t border-edge pt-4">
            <p className="text-sm font-semibold">Change the password</p>
            <div>
              <label className="label" htmlFor="current-password">
                Current password
              </label>
              <input
                id="current-password"
                type="password"
                className="field"
                autoComplete="current-password"
                value={current}
                onChange={(event) => setCurrent(event.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="new-password">
                New password (min. 12 characters)
              </label>
              <input
                id="new-password"
                type="password"
                className="field"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            <button
              type="button"
              className="btn-primary btn-sm"
              onClick={() => void changePassword()}
              disabled={busy || !current || password.length < 12}
            >
              {busy ? "Updating…" : "Update password"}
            </button>
          </div>
        </Card>

        <Card title="Security posture" bodyClassName="p-5">
          <ul className="space-y-2.5 text-sm text-ink-muted">
            <li>• Every tool call passes the deterministic policy engine and the hard guards.</li>
            <li>• Sensitive actions require an explicit human approval bound to the exact action.</li>
            <li>• Execution happens in a hardened, network-free container sandbox.</li>
            <li>• Audit records are chained with HMAC-SHA256 and can be verified at any time.</li>
            <li>• Provider credentials are encrypted at rest and never reach a sandbox worker.</li>
            <li>• Sessions use HttpOnly cookies with a signed CSRF token.</li>
          </ul>
        </Card>
      </div>
    </div>
  );
}
