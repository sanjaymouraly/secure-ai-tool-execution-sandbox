import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";

export function LoginPage() {
  const { login, error } = useAuth();
  const { theme, toggle } = useTheme();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await login(username, password);
    } catch {
      /* the error is rendered from the auth context */
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand text-lg font-bold text-white"
              aria-hidden="true"
            >
              S
            </div>
            <div>
              <h1 className="text-base font-semibold leading-tight">Secure AI Tool Execution</h1>
              <p className="text-xs text-ink-muted">Permission Sandbox</p>
            </div>
          </div>
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={toggle}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>
          </button>
        </div>

        <div className="panel p-6">
          <h2 className="text-sm font-semibold">Sign in to the control plane</h2>
          <p className="mt-1 text-xs text-ink-muted">
            Sessions are protected with an HttpOnly cookie and a CSRF token. Credentials are
            never stored in the browser.
          </p>

          <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
            <div>
              <label className="label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                name="username"
                className="field"
                autoComplete="username"
                required
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="admin"
              />
            </div>
            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                className="field"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••••••"
              />
            </div>

            {error && (
              <p
                role="alert"
                className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger"
              >
                {error}
              </p>
            )}

            <button type="submit" className="btn-primary w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>
        </div>

        <div className="panel mt-4 p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
            How authorisation works
          </p>
          <ol className="mt-2 space-y-1 text-xs text-ink-muted">
            <li>1. The model proposes a tool call — it never grants permission.</li>
            <li>2. Hard guards and the policy engine decide allow, deny or approve.</li>
            <li>3. Sensitive actions wait for an explicit human approval.</li>
            <li>4. Execution happens in an isolated, network-free sandbox.</li>
            <li>5. Every decision is written to the tamper-evident audit trail.</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
