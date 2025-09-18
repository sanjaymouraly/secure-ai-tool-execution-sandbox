# Secure AI Tool Execution &amp; Permission Sandbox — dashboard

The operator console of the Secure AI Tool Execution &amp; Permission Sandbox.
It is a React 18 + TypeScript single page application built with Vite and
Tailwind CSS 4.

```bash
npm install
npm run dev        # http://127.0.0.1:5173
npm run build      # production bundle in dist/
npm run typecheck  # tsc --noEmit
npm run lint       # oxlint
```

The dev server proxies `/api`, `/health`, `/ready`, `/overview` and `/metrics`
to the backend (set `VITE_BACKEND_URL` to change the target, default
`http://127.0.0.1:8000`).

The dashboard never stores a credential: the session lives in an HttpOnly
cookie and the CSRF token in a readable cookie that is echoed back in the
`X-CSRF-Token` header for every state-changing request.

See the [project README](../README.md) for the full documentation.
