import { useState } from "react";
import { api } from "../api/client";
import type { ProviderProfile, ProviderType } from "../api/client";
import { useApi, formatTimestamp } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";
import { Badge, Card, EmptyState, ErrorState, KeyValue, Spinner, StatusBadge } from "../components/ui";

interface ProviderListResponse {
  profiles: ProviderProfile[];
  environment: {
    default_provider: string;
    default_model: string;
    default_base_url: string;
    has_env_api_key: boolean;
    encryption_available: boolean;
  };
}

interface TypesResponse {
  types: ProviderType[];
  pricing: Record<string, { input_per_1m: number; output_per_1m: number }>;
  pricing_note: string;
}

const EMPTY_FORM = {
  name: "",
  provider_type: "ollama",
  base_url: "http://localhost:11434/v1",
  model: "",
  api_key: "",
  timeout_seconds: 120,
  max_retries: 2,
  max_tokens: 4096,
  temperature: 0.2,
  is_default: false,
};

export function ProvidersPage() {
  const { permissions } = useAuth();
  const types = useApi<TypesResponse>((signal) => api.get("/providers/types", signal), []);
  const profiles = useApi<ProviderListResponse>((signal) => api.get("/providers", signal), []);
  const [form, setForm] = useState(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [models, setModels] = useState<string[]>([]);

  async function createProfile() {
    setBusy(true);
    setError(null);
    setFlash(null);
    try {
      await api.post("/providers", {
        ...form,
        api_key: form.api_key || null,
      });
      setFlash(`Provider profile "${form.name}" created.`);
      setForm(EMPTY_FORM);
      profiles.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  async function testProfile(profile: ProviderProfile) {
    setTesting(profile.id);
    setError(null);
    setFlash(null);
    try {
      const result = await api.post<{ ok: boolean; message: string }>(
        `/providers/${profile.id}/test`,
      );
      setFlash(
        result.ok
          ? `Connection to "${profile.name}" succeeded: ${result.message}`
          : `Connection to "${profile.name}" failed: ${result.message}`,
      );
      profiles.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setTesting(null);
    }
  }

  async function discoverModels() {
    setError(null);
    setFlash(null);
    try {
      const result = await api.get<{ models: string[]; error?: string }>("/providers/models");
      if (result.error) {
        setError(result.error);
        setModels([]);
      } else {
        setModels(result.models);
        setFlash(`Discovered ${result.models.length} model(s).`);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  const selectedType = types.data?.types.find((item) => item.id === form.provider_type);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">AI provider configuration</h1>
        <p className="text-sm text-ink-muted">
          The provider is an interchangeable adapter. API keys are encrypted at rest, never
          logged, never returned to the browser and never handed to a sandbox worker.
        </p>
      </header>

      {flash && (
        <p className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-sm text-ok">{flash}</p>
      )}
      {error && <ErrorState message={error} />}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Supported providers" bodyClassName="p-5">
          {types.loading ? (
            <Spinner />
          ) : (
            <ul className="space-y-3">
              {types.data?.types.map((type) => (
                <li key={type.id} className="rounded-lg border border-edge p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-medium">{type.id}</span>
                    <Badge tone="brand">{type.format}</Badge>
                    {type.requires_key ? (
                      <Badge tone="warn">API key required</Badge>
                    ) : (
                      <Badge tone="ok">no key required</Badge>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-ink-muted">{type.notes}</p>
                  {type.default_base_url && (
                    <p className="mt-1 font-mono text-[11px] text-ink-faint">
                      {type.default_base_url}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Environment defaults" bodyClassName="p-5 space-y-4">
          {profiles.data ? (
            <>
              <KeyValue
                items={[
                  ["Default provider", profiles.data.environment.default_provider],
                  ["Default model", profiles.data.environment.default_model],
                  ["Default base URL", profiles.data.environment.default_base_url],
                  [
                    "API key in environment",
                    profiles.data.environment.has_env_api_key ? "yes" : "no",
                  ],
                  [
                    "Credential encryption",
                    profiles.data.environment.encryption_available ? "available" : "not configured",
                  ],
                ]}
              />
              <p className="text-xs text-ink-muted">
                Set <code className="font-mono">SAXIS_PROVIDER_API_KEY</code> to use a key from
                the environment. Keys stored in the UI require{" "}
                <code className="font-mono">SAXIS_PROVIDER_SECRET_KEY</code>.
              </p>
              <button type="button" className="btn-secondary btn-sm" onClick={() => void discoverModels()}>
                Discover available models
              </button>
              {models.length > 0 && (
                <div className="max-h-48 overflow-y-auto rounded-lg border border-edge p-3">
                  <ul className="space-y-1 font-mono text-[11px]">
                    {models.map((model) => (
                      <li key={model} className="truncate">
                        {model}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <Spinner />
          )}
        </Card>
      </div>

      <Card title="Configured profiles" bodyClassName="p-0">
        {profiles.loading ? (
          <Spinner />
        ) : !profiles.data || profiles.data.profiles.length === 0 ? (
          <EmptyState
            title="No provider profiles yet"
            description="Create one below, or rely on the environment defaults."
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Type</th>
                  <th scope="col">Model</th>
                  <th scope="col">Key</th>
                  <th scope="col">Last test</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {profiles.data.profiles.map((profile) => (
                  <tr key={profile.id}>
                    <td className="font-mono text-xs">
                      {profile.name}
                      {profile.is_default && (
                        <Badge tone="brand">
                          <span className="ml-1">default</span>
                        </Badge>
                      )}
                    </td>
                    <td className="text-xs">{profile.provider_type}</td>
                    <td className="font-mono text-xs text-ink-muted">{profile.model || "—"}</td>
                    <td className="text-xs text-ink-muted">
                      {profile.has_api_key ? profile.api_key_hint : "—"}
                    </td>
                    <td className="text-xs text-ink-muted">
                      {profile.last_test_at ? (
                        <span className="flex items-center gap-1.5">
                          <StatusBadge
                            status={profile.last_test_ok ? "completed" : "failed"}
                          />
                          {formatTimestamp(profile.last_test_at)}
                        </span>
                      ) : (
                        "never"
                      )}
                    </td>
                    <td className="text-right">
                      <button
                        type="button"
                        className="btn-secondary btn-sm"
                        onClick={() => void testProfile(profile)}
                        disabled={testing === profile.id}
                      >
                        {testing === profile.id ? "Testing…" : "Test connection"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {permissions.can_edit_policy && (
        <Card
          title="Add a provider profile"
          subtitle="Credentials are encrypted with the server key before they are stored."
          bodyClassName="p-5 space-y-4"
        >
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <label className="label" htmlFor="provider-name">
                Name
              </label>
              <input
                id="provider-name"
                className="field"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                placeholder="local-ollama"
              />
            </div>
            <div>
              <label className="label" htmlFor="provider-type">
                Type
              </label>
              <select
                id="provider-type"
                className="field"
                value={form.provider_type}
                onChange={(event) => {
                  const type = types.data?.types.find((item) => item.id === event.target.value);
                  setForm({
                    ...form,
                    provider_type: event.target.value,
                    base_url: type?.default_base_url ?? form.base_url,
                  });
                }}
              >
                {types.data?.types.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="provider-model">
                Model
              </label>
              <input
                id="provider-model"
                className="field font-mono text-xs"
                value={form.model}
                onChange={(event) => setForm({ ...form, model: event.target.value })}
                placeholder="qwen2.5:1.5b"
              />
            </div>
            <div className="sm:col-span-2 lg:col-span-2">
              <label className="label" htmlFor="provider-base-url">
                Base URL
              </label>
              <input
                id="provider-base-url"
                className="field font-mono text-xs"
                value={form.base_url}
                onChange={(event) => setForm({ ...form, base_url: event.target.value })}
                placeholder="https://api.openai.com/v1"
              />
            </div>
            <div>
              <label className="label" htmlFor="provider-key">
                API key {selectedType?.requires_key ? "" : "(optional)"}
              </label>
              <input
                id="provider-key"
                type="password"
                className="field"
                autoComplete="new-password"
                value={form.api_key}
                onChange={(event) => setForm({ ...form, api_key: event.target.value })}
              />
            </div>
            <div>
              <label className="label" htmlFor="provider-timeout">
                Timeout (s)
              </label>
              <input
                id="provider-timeout"
                type="number"
                className="field"
                value={form.timeout_seconds}
                onChange={(event) =>
                  setForm({ ...form, timeout_seconds: Number(event.target.value) })
                }
              />
            </div>
            <div>
              <label className="label" htmlFor="provider-tokens">
                Max tokens
              </label>
              <input
                id="provider-tokens"
                type="number"
                className="field"
                value={form.max_tokens}
                onChange={(event) =>
                  setForm({ ...form, max_tokens: Number(event.target.value) })
                }
              />
            </div>
            <div>
              <label className="label" htmlFor="provider-temperature">
                Temperature
              </label>
              <input
                id="provider-temperature"
                type="number"
                step="0.1"
                className="field"
                value={form.temperature}
                onChange={(event) =>
                  setForm({ ...form, temperature: Number(event.target.value) })
                }
              />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-ink-muted">
              <input
                type="checkbox"
                checked={form.is_default}
                onChange={(event) => setForm({ ...form, is_default: event.target.checked })}
              />
              Make this the default profile
            </label>
            <button
              type="button"
              className="btn-primary"
              onClick={() => void createProfile()}
              disabled={busy || !form.name}
            >
              {busy ? "Saving…" : "Create profile"}
            </button>
          </div>
        </Card>
      )}

      {types.data && (
        <Card title="Price list used for cost estimates" bodyClassName="p-5">
          <p className="mb-3 text-xs text-ink-muted">{types.data.pricing_note}</p>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Model family</th>
                  <th scope="col">Input $/1M</th>
                  <th scope="col">Output $/1M</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(types.data.pricing).map(([model, price]) => (
                  <tr key={model}>
                    <td className="font-mono text-xs">{model}</td>
                    <td className="tabular-nums text-xs">${price.input_per_1m.toFixed(4)}</td>
                    <td className="tabular-nums text-xs">${price.output_per_1m.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
