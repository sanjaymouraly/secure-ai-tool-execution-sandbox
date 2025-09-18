import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { rootFetch } from "../api/client";
import type { SandboxStatus } from "../api/client";
import { Badge } from "./ui";

interface NavItem {
  to: string;
  label: string;
  icon: string;
  description: string;
}

const NAV_SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: "Monitor",
    items: [
      { to: "/", label: "Overview", icon: "▤", description: "Activity and security metrics" },
      { to: "/executions", label: "Executions", icon: "▷", description: "Every tool invocation" },
      { to: "/audit", label: "Audit trail", icon: "❐", description: "Tamper-evident records" },
    ],
  },
  {
    title: "Control",
    items: [
      { to: "/agent", label: "Agent", icon: "◈", description: "Chat and live trace" },
      { to: "/approvals", label: "Approvals", icon: "✓", description: "Human approval queue" },
      { to: "/policies", label: "Policies", icon: "⚖", description: "Permission policy editor" },
      { to: "/tools", label: "Tools", icon: "⚙", description: "Tool registry" },
    ],
  },
  {
    title: "Environment",
    items: [
      { to: "/workspace", label: "Workspace", icon: "▦", description: "Approved files" },
      { to: "/sandbox", label: "Sandbox", icon: "⛨", description: "Isolation posture" },
      { to: "/attack-lab", label: "Attack lab", icon: "⚠", description: "Prompt-injection scenarios" },
      { to: "/providers", label: "Providers", icon: "◍", description: "AI provider settings" },
      { to: "/settings", label: "Settings", icon: "⚒", description: "System health" },
    ],
  },
];

export function Layout() {
  const { user, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const location = useLocation();
  const [sandbox, setSandbox] = useState<SandboxStatus | null>(null);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    let active = true;
    rootFetch<{ sandbox: SandboxStatus }>("/ready")
      .then((data) => {
        if (active) setSandbox(data.sandbox);
      })
      .catch(() => {
        if (active) setSandbox(null);
      });
    return () => {
      active = false;
    };
  }, [location.pathname]);
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen bg-surface">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-edge bg-surface-raised
                    transition-transform lg:static lg:translate-x-0 ${
                      navOpen ? "translate-x-0" : "-translate-x-full"
                    }`}
        aria-label="Primary navigation"
      >
        <div className="flex items-center gap-3 border-b border-edge px-5 py-4">
          <div
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand text-base font-bold text-white"
            aria-hidden="true"
          >
            S
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold leading-tight">Secure AI Sandbox</p>
            <p className="truncate text-xs text-ink-muted">Tool execution &amp; permissions</p>
          </div>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title}>
              <p className="px-2 pb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">
                {section.title}
              </p>
              <ul className="space-y-0.5">
                {section.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.to === "/"}
                      className={({ isActive }) =>
                        `flex items-start gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors ${
                          isActive
                            ? "bg-brand/10 font-medium text-brand"
                            : "text-ink-muted hover:bg-surface-sunken hover:text-ink"
                        }`
                      }
                    >
                      <span className="mt-0.5 w-4 text-center text-xs" aria-hidden="true">
                        {item.icon}
                      </span>
                      <span className="min-w-0">
                        <span className="block leading-tight">{item.label}</span>
                        <span className="block truncate text-[11px] text-ink-faint">
                          {item.description}
                        </span>
                      </span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="space-y-3 border-t border-edge px-4 py-4">
          {sandbox && (
            <div className="rounded-lg border border-edge bg-surface-sunken p-3">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-faint">
                Sandbox
              </p>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <Badge tone={sandbox.available ? "ok" : "danger"}>
                  {sandbox.available ? "available" : "unavailable"}
                </Badge>
                <Badge tone={sandbox.isolated ? "ok" : "warn"}>
                  {sandbox.isolated ? "isolated" : "simulated"}
                </Badge>
              </div>
            </div>
          )}
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user?.username ?? "—"}</p>
              <p className="truncate text-xs capitalize text-ink-muted">{user?.role ?? ""}</p>
            </div>
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => void logout()}
              title="Sign out"
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>

      {navOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-edge bg-surface/90 px-4 py-3 backdrop-blur lg:px-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="btn-ghost btn-sm lg:hidden"
              onClick={() => setNavOpen((open) => !open)}
              aria-label="Toggle navigation"
            >
              ☰
            </button>
            <p className="text-sm text-ink-muted">
              Deny-by-default policy engine · independent authorization · isolated execution
            </p>
          </div>
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={toggle}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </header>

        <main className="min-w-0 flex-1 px-4 py-6 lg:px-8">
          <Outlet />
        </main>

        <footer className="border-t border-edge px-4 py-4 text-xs text-ink-faint lg:px-8">
          Secure AI Tool Execution &amp; Permission Sandbox — LLM proposals are never
          permissions. Every action is authorised server side and executed in isolation.
        </footer>
      </div>
    </div>
  );
}
