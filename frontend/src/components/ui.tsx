import type { ReactNode } from "react";

/* ------------------------------------------------------------------ badge */

const TONES = {
  neutral: "border-edge bg-surface-sunken text-ink-muted",
  ok: "border-ok/30 bg-ok/10 text-ok",
  warn: "border-warn/30 bg-warn/10 text-warn",
  danger: "border-danger/30 bg-danger/10 text-danger",
  info: "border-info/30 bg-info/10 text-info",
  brand: "border-brand/30 bg-brand/10 text-brand",
} as const;

export type BadgeTone = keyof typeof TONES;

export function Badge({
  tone = "neutral",
  children,
  title,
}: {
  tone?: BadgeTone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`chip ${TONES[tone]}`} title={title}>
      {children}
    </span>
  );
}

const STATUS_TONES: Record<string, BadgeTone> = {
  completed: "ok",
  allowed: "ok",
  approved: "ok",
  pass: "ok",
  passed: "ok",
  active: "ok",
  available: "ok",
  healthy: "ok",
  ready: "ok",
  denied: "danger",
  failed: "danger",
  error: "danger",
  blocked: "danger",
  timeout: "danger",
  timed_out: "danger",
  awaiting_approval: "warn",
  pending: "warn",
  approval: "warn",
  require_approval: "warn",
  running: "info",
  degraded: "warn",
  cancelled: "neutral",
  skipped: "neutral",
  low: "neutral",
  medium: "warn",
  high: "danger",
  critical: "danger",
};

export function statusTone(status: string | null | undefined): BadgeTone {
  if (!status) return "neutral";
  return STATUS_TONES[status.toLowerCase()] ?? "neutral";
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <Badge tone="neutral">unknown</Badge>;
  return <Badge tone={statusTone(status)}>{status.replace(/_/g, " ")}</Badge>;
}

/* ------------------------------------------------------------------- card */

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
  bodyClassName = "p-5",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          <div>
            {title && <h2 className="panel-title">{title}</h2>}
            {subtitle && <p className="panel-subtitle mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------------ stats */

export function Stat({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: BadgeTone;
}) {
  const toneClass =
    tone === "ok"
      ? "text-ok"
      : tone === "warn"
        ? "text-warn"
        : tone === "danger"
          ? "text-danger"
          : tone === "info"
            ? "text-info"
            : "text-ink";
  return (
    <div className="rounded-lg border border-edge bg-surface-raised p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-ink-muted">{label}</p>
      <p className={`mt-1.5 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  );
}

/* ----------------------------------------------------------------- states */

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-10 text-sm text-ink-muted">
      <span
        className="h-4 w-4 animate-spin rounded-full border-2 border-edge border-t-brand"
        aria-hidden="true"
      />
      <span>{label}…</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {description && <p className="max-w-md text-sm text-ink-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-danger/30 bg-danger/5 p-4"
    >
      <div>
        <p className="text-sm font-semibold text-danger">Something went wrong</p>
        <p className="mt-1 break-words text-sm text-ink-muted">{message}</p>
      </div>
      {onRetry && (
        <button type="button" className="btn-secondary btn-sm" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ misc */

export function KeyValue({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
      {items.map(([key, value]) => (
        <div key={key} className="min-w-0">
          <dt className="text-xs font-medium uppercase tracking-wide text-ink-faint">{key}</dt>
          <dd className="mt-0.5 break-words text-sm text-ink">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ProgressBar({ value, tone = "brand" }: { value: number; tone?: BadgeTone }) {
  const clamped = Math.max(0, Math.min(100, value * 100));
  const barClass =
    tone === "ok"
      ? "bg-ok"
      : tone === "warn"
        ? "bg-warn"
        : tone === "danger"
          ? "bg-danger"
          : "bg-brand";
  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-surface-sunken"
      role="progressbar"
      aria-valuenow={Math.round(clamped)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className={`h-full rounded-full ${barClass}`} style={{ width: `${clamped}%` }} />
    </div>
  );
}
