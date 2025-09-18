import { rootFetch } from "../api/client";
import type { SandboxStatus } from "../api/client";
import { useApi } from "../hooks/useApi";
import { Badge, Card, ErrorState, KeyValue, Spinner, StatusBadge } from "../components/ui";

interface ReadyResponse {
  status: string;
  database: string;
  sandbox: SandboxStatus;
  policy_version: string;
  timestamp: string;
}

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

export function SandboxPage() {
  const ready = useApi<ReadyResponse>((signal) => rootFetch<ReadyResponse>("/ready", signal), []);
  const info = useApi<SystemInfo>((signal) => rootFetch<SystemInfo>("/system/info", signal), []);

  if (ready.loading) return <Spinner label="Inspecting the sandbox" />;
  if (ready.error) return <ErrorState message={ready.error} onRetry={ready.reload} />;
  if (!ready.data) return null;

  const sandbox = ready.data.sandbox;

  const controls: Array<[string, boolean, string]> = [
    [
      "Real OS-level isolation",
      sandbox.isolated,
      sandbox.isolated
        ? "The backend starts a separate container for every execution."
        : "SIMULATION MODE — no operating system isolation. Never use it for untrusted code.",
    ],
    ["Read-only root filesystem", true, "The container root is mounted read-only; only /tmp is writable."],
    ["All capabilities dropped", true, "The container starts with --cap-drop ALL."],
    ["No new privileges", true, "no-new-privileges is set on every container."],
    ["Seccomp filter", sandbox.seccomp, "A hardened profile removes namespace, tracing and eBPF syscalls."],
    ["AppArmor profile", sandbox.apparmor, "The host AppArmor profile is applied when available."],
    ["Network denied", true, "The container has no network namespace and no route to the host."],
    ["User namespace isolation", sandbox.user_namespaces, "Enabled when the daemon runs rootless."],
    ["Rootless daemon", sandbox.rootless, "The Docker daemon itself runs without root."],
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Sandbox status</h1>
          <p className="text-sm text-ink-muted">
            The isolation posture of the execution backend, read from the running system.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status={ready.data.status} />
          <Badge tone={sandbox.available ? "ok" : "danger"}>
            {sandbox.available ? "available" : "unavailable"}
          </Badge>
          <Badge tone={sandbox.isolated ? "ok" : "warn"}>
            {sandbox.isolated ? "isolated" : "simulated"}
          </Badge>
        </div>
      </header>

      {sandbox.warnings.length > 0 && (
        <div className="rounded-lg border border-warn/30 bg-warn/5 p-4">
          <p className="text-sm font-semibold text-warn">Deployment notes</p>
          <ul className="mt-1.5 space-y-1 text-sm text-ink-muted">
            {sandbox.warnings.map((warning) => (
              <li key={warning}>• {warning}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Enforced controls" bodyClassName="p-5">
          <ul className="space-y-3">
            {controls.map(([label, enabled, description]) => (
              <li key={label} className="flex items-start gap-3">
                <span
                  className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${
                    enabled ? "bg-ok/15 text-ok" : "bg-warn/15 text-warn"
                  }`}
                  aria-hidden="true"
                >
                  {enabled ? "✓" : "!"}
                </span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium">{label}</span>
                  <span className="block text-xs text-ink-muted">{description}</span>
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <div className="space-y-6">
          <Card title="Backend" bodyClassName="p-5">
            <KeyValue
              items={[
                ["Backend", sandbox.name],
                ["Image", sandbox.image],
                ["Docker version", sandbox.version || "—"],
                ["Readiness", ready.data.status],
                ["Database", ready.data.database],
                ["Policy version", ready.data.policy_version],
              ]}
            />
          </Card>

          {info.data && (
            <Card title="Deployment" bodyClassName="p-5">
              <KeyValue
                items={[
                  ["Service", info.data.name],
                  ["Version", info.data.version],
                  ["Environment", info.data.environment],
                  ["Python", info.data.python],
                  ["Platform", info.data.platform],
                  ["Auth mode", info.data.auth_mode],
                  ["Configured backend", info.data.sandbox_backend],
                  ["API prefix", info.data.api_prefix],
                  ["Uptime", `${Math.round(info.data.uptime_seconds)} s`],
                ]}
              />
            </Card>
          )}

          <Card title="What this does not protect against" bodyClassName="p-5">
            <ul className="space-y-1.5 text-sm text-ink-muted">
              <li>• Kernel level vulnerabilities in the host or the container runtime.</li>
              <li>• Container escape exploits that defeat seccomp, namespaces and capabilities.</li>
              <li>• A compromised Docker daemon or a rootful daemon on a shared host.</li>
              <li>• Denial of service against the host itself (CPU, memory, disk exhaustion).</li>
              <li>• Side channels such as timing, resource contention and metadata leakage.</li>
            </ul>
            <p className="mt-3 text-xs text-ink-faint">
              For stronger isolation use gVisor, Firecracker or a microVM backend; the broker
              interface allows a drop-in replacement.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}
