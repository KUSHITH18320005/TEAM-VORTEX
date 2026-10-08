# MAD-PS SENTINEL™ — MNC-Grade Design System Specification

## 1. Core Philosophy
MAD-PS SENTINEL™ is an enterprise-grade autonomous multi-agent cyber defense platform. The UI/UX balances authoritative security engineering rigor with modern developer-tool aesthetics (Linear, Wiz, Sentry, Vercel). The interface is content-forward, prioritizing real data visualizations (8-model detection scores, live Council deliberations, passive telemetry) over decorative generic shapes.

---

## 2. Color System & Signature Treatment

### 2.1 Canvas & Surface Hierarchy
- **Base Canvas (Dark)**: `#0A0A0E` (Deep warm charcoal, avoiding flat pitch black).
- **Base Canvas (Light)**: `#F8FAFC` (Crisp off-white / slate).
- **Layered Surfaces**:
  - `Surface Level 1 (Cards)`: `rgba(18, 18, 24, 0.75)` with `backdrop-filter: blur(12px)`.
  - `Surface Level 2 (Elevated Panels)`: `rgba(24, 24, 32, 0.90)`.
  - `Surface Level 3 (Inputs & Recesses)`: `rgba(12, 12, 16, 0.85)`.

### 2.2 Brand Identity Accent
- **Signature Accent**: Deep Indigo-Violet (`#6366F1` base / `#818CF8` hover / `#4F46E5` active).
  - Background Tint: `rgba(99, 102, 241, 0.08)`.
  - Border Highlight: `rgba(99, 102, 241, 0.28)`.
  - Soft Glow: `0 8px 30px rgba(99, 102, 241, 0.12)`.

### 2.3 Functional Status Accents
- **Nominal / Verified (Emerald)**: `#10B981` (`rgba(16, 185, 129, 0.10)` background).
- **Critical Anomaly (Rose)**: `#F43F5E` (`rgba(244, 63, 94, 0.10)` background).
- **Warning / Review (Amber)**: `#F59E0B` (`rgba(245, 158, 11, 0.10)` background).
- **Judicial Gilded Accent**: `#EAB308` / `#FACC15` (Chief Magistrate synthesis).

### 2.4 Signature Background Treatment
- Large soft radial ambient illumination centered above the hero:
  `radial-gradient(ellipse 80% 50% at 50% -20%, rgba(99, 102, 241, 0.16), transparent 70%)`
- Faint precision mesh grid:
  `40px 40px` grid with `rgba(255, 255, 255, 0.018)` stroke.

---

## 3. Typography Architecture

| Category | Typeface | Weights | Usage |
| :--- | :--- | :--- | :--- |
| **Headlines & Display** | `Outfit`, `Plus Jakarta Sans`, sans-serif | `700`, `800` | Hero copy (`54px-62px`), Section headers (`32px`), Feature titles (`18px-22px`). Tight letter-spacing (`-0.035em`). |
| **Body & UI Controls** | `Inter`, -apple-system, sans-serif | `400`, `500`, `600` | Navigation, descriptions, button labels, table text, form inputs. |
| **Data & Forensics** | `JetBrains Mono`, `Geist Mono`, monospace | `400`, `500`, `600`, `700` | Model scores (`0.00-1.00`), P95 latencies, ports (`:8002`), timestamps, payload previews. |

---

## 4. Layout & Surface Patterns

### 4.1 Asymmetric Content-Forward Hero
- **Left Column (~55%)**: High-clarity message, badge, CTAs, and asymmetric numerical proof points with accent brackets.
- **Right Column (~45%)**: Realistic macOS/SaaS browser chrome previewing the real **8-Model Consensus Mesh Matrix** with live score progress meters.

### 4.2 Dense 8-Model Zoo
- 8 independent model cards presenting model name, port, core algorithm, benchmark metric, and empirical detection focus.

### 4.3 Tactile Cards & Micro-Interactions
- Hairline borders: `1px solid rgba(255, 255, 255, 0.08)`.
- Interactive hover: `border-color: rgba(99, 102, 241, 0.35)`, `transform: translateY(-2px)`, `box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3), 0 0 20px rgba(99, 102, 241, 0.10)`.
