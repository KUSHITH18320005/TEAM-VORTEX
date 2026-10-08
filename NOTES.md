# UI/UX Engineering Notes — Directive v2

## 1. Structural Markup Updates
1. **Hero Asymmetry (`landing.html`)**:
   - Transformed hero from centered stack into an asymmetric 2-column grid (`.hero-grid-2col`).
   - Left side: Badge pill, 56px headline with gradient accent, subtitle, CTA group, and 3 key metrics with accent bracket underlines.
   - Right side: Realistic browser container (`.browser-mockup-frame`) hosting the live 8-Model Consensus Mesh Matrix visual with dynamic gauges and active consensus verdict chip.

2. **Typography Font Inclusions**:
   - Added Google Font links for `Outfit:wght@400;600;700;800`, `Plus+Jakarta+Sans:wght@500;600;700;800`, `Inter:wght@400;500;600`, and `JetBrains+Mono:wght@400;500;600;700` across all HTML templates.

3. **8-Model Zoo Section**:
   - Structured into an 8-card responsive matrix showcasing real model ports (`:8002` - `:8008`), algorithm tags, and empirical benchmarks.

4. **Preserved Logic & Zero Scope Violations**:
   - All IDs, data attributes, WebSocket endpoints (`/ws/council`), API routes (`/api/v1/...`), auth storage (`madps_token`, `madps_org`), and MADDY AI communication streams are 100% preserved.
