# AutoSecTwin Frontend — Remaining Tasks

## What is complete and working

- Vite + React + TypeScript + Tailwind v4 scaffold
- Space-station theme: dark navy/charcoal, neon cyan/blue/purple, panel cards, pulse animations
- Dev-server proxy to the FastAPI backend (`vite.config.ts`)
- Full TypeScript types matching the live backend OpenAPI schema (`src/lib/types.ts`)
- API client with typed error handling (`src/lib/apiClient.ts`)
- 11 typed API modules covering every backend endpoint group
- `useAsync` data-fetching hook
- Shared components: StatusBadge, MissionCard, MetricTile, Button, LoadingState, EmptyState, ErrorState, ConfirmDialog
- Layout: TopNav (sticky, space-station branding, all nav items), PageShell
- **Dashboard** — live metrics from 4 real API calls, recent remediation/twin activity, quick actions
- **Register Target** (Feature 1) — URL input with validation, drag-drop file upload, folder selection, authorization checkbox, honest integration-boundary note explaining what backend work is still needed for real URL/upload scanning
- **Reports Center** (Feature 2) — real API listing, type filters, GET REPORTS button, link to detail
- **Report Detail** — iframe HTML render, PDF download via the existing `/reports/{id}/pdf` route
- **Human Approval Center** (Feature 3) — full queue, reviewer identity + reason fields, Approve/Reject with confirmation, Execute Remediation with destructive-action confirmation dialog, Revalidate, Generate Report, real status polling
- **Digital Twin Fleet** — inventory grid with search, link to viewer
- **Digital Twin Viewer** (Feature 4) — full metadata display, full-screen mode, Destroy Twin with confirmation
- **Vulnerabilities** — full table from real API
- **System Health** — trust statistics + model drift from real API
- TypeScript: 0 errors
- oxlint: 0 warnings, 0 errors
- Production build: clean, 304 kB JS / 32 kB CSS

## How to run it

```bash
# 1. Install dependencies (from the frontend/ directory)
cd frontend
npm install

# 2. Start backend (from the repo root)
#    Make sure your .env has MOCK_MODE=true for a local demo
python3 -m uvicorn main:app --host 127.0.0.1 --port 8000

# 3. Start the frontend dev server
cd frontend
npm run dev
# Opens at http://localhost:5173
```

## Environment variables (frontend/.env)

```
# Optional — leave unset to use the Vite dev proxy (http://127.0.0.1:8000)
VITE_BACKEND_URL=http://127.0.0.1:8000
```

## Remaining tasks

### 1. Google Fonts / custom typefaces
`Orbitron` and `Rajdhani` (referenced in `index.css`) need to be either:
- Added as a `<link>` in `index.html` via Google Fonts CDN, or
- Downloaded and placed in `public/fonts/` with corresponding `@font-face` rules.
Without them the browser falls back to `ui-sans-serif`; the layout still works,
but the space-station aesthetic is diminished.

Add to `index.html` `<head>`:
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=Rajdhani:wght@400;500;600&display=swap" rel="stylesheet">
```

### 2. Register Target — real backend scanning
The current UI captures a URL and uploaded archive correctly, but the
backend has no endpoint to accept them and run a real scan. Backend work
required:
- `POST /assets/` — accept URL or uploaded archive
- A scanner/crawler integration to discover CVEs in the target
- Linking the result back to a `Vulnerability` row

Until that exists, the frontend shows an honest "registered but not scanned"
banner, which is the correct behavior.

### 3. Orchestration job — start from UI
`POST /orchestration/run` exists and works. The "Start Security Assessment"
button currently just registers the target on the frontend. Wiring it to
actually call `/orchestration/run` for an existing `vulnerability_id` is a
one-function addition to `RegisterTarget.tsx` once the user can select an
existing vulnerability in that form.

### 4. Responsive mobile nav
The `TopNav` hides the nav items on small screens (`hidden lg:flex`) with
no hamburger menu replacement. Add a slide-out drawer or bottom bar for
mobile.

### 5. Pagination / infinite scroll
All list pages fetch everything in one call. For large datasets, add
pagination to the Vulnerabilities, Reports, and Approvals pages once the
backend exposes `?page=` or `?limit=&offset=` query params.

### 6. CORS for production deployment
The Vite dev proxy handles CORS in dev. For a real deployment, either:
- Configure FastAPI with `CORSMiddleware` allowing the frontend's origin, or
- Put both behind the same reverse proxy (nginx/caddy).

### 7. Authentication
No auth is implemented on either the frontend or backend. Before any
internet-facing deployment, add at minimum a backend API key or session
mechanism, and a login page on the frontend.

### 8. Backend migration conflict
The remote GitHub repo has a second Alembic migration branch
(`0003_closed_loop_orchestration` → `0004_orchestration_queue_backend`)
that conflicts with the Phase 0 branch delivered in
`autosectwin_remediation_changes.zip`. The `0004` migration uses
Postgres-only `ALTER COLUMN ... DROP NOT NULL` syntax (incompatible with
SQLite dev/test). Resolve before running `alembic upgrade head` in an
environment with both branches present.

### 9. Minor visual polish opportunities (low priority)
- Animated scan-line on the TwinViewer full-screen mode
- A real star-field/particle background (CSS only, no heavy lib needed)
- Toast notifications for approve/reject/execute success instead of
  inline error text only
- Dark/light mode toggle (the theme variables are already structured
  for it; only `@media (prefers-color-scheme: light)` overrides are missing)
