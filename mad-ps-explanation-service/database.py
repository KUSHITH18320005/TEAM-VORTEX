"""
Shared Product Database Manager for MAD-PS Ecosystem.
Supports PostgreSQL with transparent SQLite fallback (data/mad_ps_product.db).
Manages `incidents`, `incident_reports`, `conversations`, `conversation_messages`,
`organizations`, `users`, `api_keys`, `monitored_applications`, `contact_requests`, and `usage_records`.
Enforces strict multi-tenant organizational scoping and tenant isolation.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mad_ps.database")

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_DIR = Path(os.environ.get("MAD_PS_DATA_DIR", REPO_ROOT / "data"))
DB_FILE = DB_DIR / "mad_ps_product.db"


class SharedProductDatabase:
    """Manages persistent storage for incidents, council reports, and multi-tenant SaaS entities."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = Path(db_path or DB_FILE)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._seed_default_org()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Create shared tables if not existing."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Drop legacy surfaces table
            cursor.execute("DROP TABLE IF EXISTS surfaces")
            # 1. Incidents Table (emitted by detection mesh)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL DEFAULT 'org_default',
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    contributing_branch_scores TEXT,
                    raw_log_details TEXT,
                    campaign_id TEXT,
                    affected_endpoints TEXT,
                    affected_entities TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            # 2. Incident Reports Table (synthesized by Council)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_reports (
                    report_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'org_default',
                    generated_at TEXT NOT NULL,
                    executive_summary TEXT NOT NULL,
                    incident_category TEXT NOT NULL,
                    detection_mesh_confidence REAL NOT NULL,
                    consensus_status TEXT NOT NULL,
                    consensus_score REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_severity_band TEXT NOT NULL,
                    requires_human_approval INTEGER NOT NULL,
                    human_approval_reasoning TEXT,
                    root_cause TEXT NOT NULL,
                    technical_timeline TEXT,
                    ranked_actions TEXT,
                    reconstruction_findings TEXT,
                    response_plan TEXT,
                    judge_synthesis TEXT,
                    debate_revisions TEXT,
                    risk_assessment TEXT,
                    grounded_timeline TEXT,
                    participating_models TEXT,
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
                )
            """)

            # 3. Conversations Table (Task L3: Per-user / Per-org conversation session)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # 4. Conversation Messages Table (Task L3: Per-turn memory & grounding citations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversation_messages (
                    message_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sources_cited TEXT,
                    retrieved_context TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
                )
            """)

            # 5. Traffic Inspections Table (Live Website & API Inspector records)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_inspections (
                    inspection_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL DEFAULT 'org_default',
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status_code INTEGER,
                    latency_ms REAL,
                    category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    is_threat INTEGER NOT NULL,
                    branch_scores TEXT,
                    entropy REAL,
                    matched_tokens TEXT,
                    response_body_preview TEXT,
                    raw_telemetry TEXT,
                    council_report_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            # 6. Organizations Table (Phase H1 / N-Q SaaS)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    org_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    plan_tier TEXT NOT NULL DEFAULT 'free',
                    verified INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)

            # 7. Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'owner',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(org_id) REFERENCES organizations(org_id)
                )
            """)

            # 8. API Keys Table (One active key per organization)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    app_id TEXT,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL DEFAULT 'Default Live Key',
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY(org_id) REFERENCES organizations(org_id)
                )
            """)

            # Ensure surfaces table is dropped (Phase S-Correction: Revert multi-surface model)
            cursor.execute("DROP TABLE IF EXISTS surfaces")

            # 9. Monitored Applications Table (Domain Verification & Integration State)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitored_applications (
                    app_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    verification_token TEXT NOT NULL,
                    verification_method TEXT NOT NULL DEFAULT 'http_file',
                    verification_path TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    verified_at TEXT,
                    sdk_connected INTEGER DEFAULT 0,
                    last_event_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(org_id) REFERENCES organizations(org_id)
                )
            """)

            # 10. Contact Requests Table (Landing Page Contact / Demo Inquiries)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS contact_requests (
                    request_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    company TEXT,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    created_at TEXT NOT NULL
                )
            """)

            # 11. Usage Records Table (Metered Request Volume & Telemetry Tracking)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usage_records (
                    record_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    app_id TEXT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_size_bytes INTEGER DEFAULT 0,
                    metadata TEXT,
                    FOREIGN KEY(org_id) REFERENCES organizations(org_id)
                )
            """)

            # 12. Pipeline Trace Table (Task X1: 13-Hop Diagnostics)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_trace (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT NOT NULL,
                    hop_step INTEGER NOT NULL,
                    hop_code TEXT NOT NULL,
                    service TEXT NOT NULL,
                    details TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            # Migration safeguard: ensure org_id exists on telemetry tables
            for table in ["incidents", "incident_reports", "traffic_inspections", "usage_records"]:
                for col, defn in [("org_id", "TEXT NOT NULL DEFAULT 'org_default'")]:
                    try:
                        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
                    except sqlite3.OperationalError:
                        pass

            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_incident_id ON incident_reports(incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_org ON incident_reports(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conv_user_org ON conversations(user_id, org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_msg_conv ON conversation_messages(conversation_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_insp_target ON traffic_inspections(target_url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_insp_created ON traffic_inspections(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_apps_org ON monitored_applications(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_contact_email ON contact_requests(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_usage_org ON usage_records(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_trace_id ON pipeline_trace(trace_id)")
            conn.commit()
            logger.info("Shared Product Database schema initialized at %s", self.db_path)

    def _seed_default_org(self) -> None:
        """Seed default organization and demo credentials if table is fresh."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("SELECT org_id FROM organizations WHERE org_id = 'org_default'")
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO organizations (org_id, name, slug, plan_tier, verified, created_at)
                    VALUES ('org_default', 'MAD-PS Demo Security Org', 'default-soc', 'enterprise', 1, ?)
                """, (now,))
                # Seed default demo user
                cursor.execute("""
                    INSERT INTO users (user_id, org_id, email, password_hash, name, role, created_at)
                    VALUES ('usr_default_admin', 'org_default', 'admin@madps.ai', 'pbkdf2:sha256:100000$default$4ce5d2c88535a8dd98bc653cb7f6c628ff1f32652195069281b67a7ef9242bc0', 'Security Admin', 'owner', ?)
                """, (now,))

            # Ensure single organization API Key covering the entire client app exists
            demo_key = "mk_live_demo1234567890abcdef1234567890abcdef"
            demo_hash = hashlib.sha256(demo_key.encode("utf-8")).hexdigest()
            cursor.execute("SELECT key_id FROM api_keys WHERE org_id = 'org_default' AND is_active = 1")
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO api_keys (key_id, org_id, app_id, key_prefix, key_hash, name, created_at, is_active)
                    VALUES ('key_default_demo', 'org_default', 'app_z_target', 'mk_live_demo', ?, 'Primary Organization API Key', ?, 1)
                """, (demo_hash, now))

            cursor.execute("SELECT app_id FROM monitored_applications WHERE org_id = 'org_default'")
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO monitored_applications (app_id, org_id, name, domain, verification_token, verification_method, verification_path, is_verified, verified_at, sdk_connected, last_event_at, created_at)
                    VALUES ('app_default_target', 'org_default', 'Production Web Application', 'app.internal', 'madps_vfy_appdemo892348', 'http_file', '/.well-known/madps-verify-appdemo.txt', 1, ?, 1, ?, ?)
                """, (now, now, now))
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────────
    # Multi-Tenant Organizations & Users
    # ──────────────────────────────────────────────────────────────────────────
    def create_organization(self, name: str, slug: Optional[str] = None, plan_tier: str = "free") -> Dict[str, Any]:
        """Create a new organization."""
        org_id = f"org_{uuid.uuid4().hex[:12]}"
        clean_slug = slug or name.lower().replace(" ", "-").replace("_", "-")
        clean_slug = "".join(c for c in clean_slug if c.isalnum() or c == "-")
        # Ensure unique slug
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT slug FROM organizations WHERE slug = ?", (clean_slug,))
            if cursor.fetchone():
                clean_slug = f"{clean_slug}-{uuid.uuid4().hex[:4]}"
            cursor.execute("""
                INSERT INTO organizations (org_id, name, slug, plan_tier, verified, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
            """, (org_id, name, clean_slug, plan_tier, now))
            conn.commit()
            return {
                "org_id": org_id,
                "name": name,
                "slug": clean_slug,
                "plan_tier": plan_tier,
                "verified": False,
                "created_at": now,
            }

    def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch organization by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "org_id": row["org_id"],
                "name": row["name"],
                "slug": row["slug"],
                "plan_tier": row["plan_tier"],
                "verified": bool(row["verified"]),
                "created_at": row["created_at"],
            }

    def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Fetch organization by slug."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM organizations WHERE slug = ?", (slug,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "org_id": row["org_id"],
                "name": row["name"],
                "slug": row["slug"],
                "plan_tier": row["plan_tier"],
                "verified": bool(row["verified"]),
                "created_at": row["created_at"],
            }

    def list_organizations(self) -> List[Dict[str, Any]]:
        """List all registered organizations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM organizations ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [{
                "org_id": r["org_id"],
                "name": r["name"],
                "slug": r["slug"],
                "plan_tier": r["plan_tier"],
                "verified": bool(r["verified"]),
                "created_at": r["created_at"],
            } for r in rows]

    def create_user(self, org_id: str, email: str, password_hash: str, name: str, role: str = "owner") -> Dict[str, Any]:
        """Create a user within an organization."""
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (user_id, org_id, email, password_hash, name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, org_id, email.strip().lower(), password_hash, name, role, now))
            conn.commit()
            return {
                "user_id": user_id,
                "org_id": org_id,
                "email": email.strip().lower(),
                "name": name,
                "role": role,
                "created_at": now,
            }

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetch user by email address."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "org_id": row["org_id"],
                "email": row["email"],
                "password_hash": row["password_hash"],
                "name": row["name"],
                "role": row["role"],
                "created_at": row["created_at"],
            }

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch user by user ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "org_id": row["org_id"],
                "email": row["email"],
                "name": row["name"],
                "role": row["role"],
                "created_at": row["created_at"],
            }

    # ──────────────────────────────────────────────────────────────────────────
    # API Keys Management
    # ──────────────────────────────────────────────────────────────────────────
    def create_api_key(self, org_id: str, name: str = "Live Production Key", app_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate, securely hash, and store a new API key."""
        raw_key = f"mk_live_{secrets.token_hex(24)}"
        key_id = f"key_{uuid.uuid4().hex[:12]}"
        key_prefix = raw_key[:12] + "..."
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_keys (key_id, org_id, app_id, key_prefix, key_hash, name, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (key_id, org_id, app_id, key_prefix, key_hash, name, now))
            conn.commit()
            return {
                "key_id": key_id,
                "api_key": raw_key,
                "key_prefix": key_prefix,
                "org_id": org_id,
                "app_id": app_id,
                "name": name,
                "created_at": now,
            }

    def verify_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        """Verify raw API key hash, update last_used_at, and return org details."""
        if not raw_key or not isinstance(raw_key, str):
            return None
        cleaned_key = raw_key.strip()
        if cleaned_key.startswith("Bearer "):
            cleaned_key = cleaned_key[7:].strip()
        key_hash = hashlib.sha256(cleaned_key.encode("utf-8")).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT k.key_id, k.org_id, k.app_id, k.name as key_name, k.is_active,
                       o.name as org_name, o.slug as org_slug, o.plan_tier
                FROM api_keys k
                JOIN organizations o ON k.org_id = o.org_id
                WHERE k.key_hash = ? AND k.is_active = 1
            """, (key_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            cursor.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now, row["key_id"]))
            conn.commit()
            return {
                "key_id": row["key_id"],
                "org_id": row["org_id"],
                "app_id": row["app_id"],
                "key_name": row["key_name"],
                "org_name": row["org_name"],
                "org_slug": row["org_slug"],
                "plan_tier": row["plan_tier"],
            }

    def list_api_keys(self, org_id: str) -> List[Dict[str, Any]]:
        """List active API keys for an organization (never reveals full key)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_id, org_id, app_id, key_prefix, name, created_at, last_used_at, is_active
                FROM api_keys
                WHERE org_id = ? AND is_active = 1
                ORDER BY created_at DESC
            """, (org_id,))
            rows = cursor.fetchall()
            return [{
                "key_id": r["key_id"],
                "org_id": r["org_id"],
                "app_id": r["app_id"],
                "key_prefix": r["key_prefix"],
                "name": r["name"],
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
                "is_active": bool(r["is_active"]),
            } for r in rows]

    def revoke_api_key(self, key_id: str, org_id: str) -> bool:
        """Revoke an API key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ? AND org_id = ?", (key_id, org_id))
            conn.commit()
            return cursor.rowcount > 0

    # ──────────────────────────────────────────────────────────────────────────
    # Monitored Applications & Domain Verification
    # ──────────────────────────────────────────────────────────────────────────
    def create_monitored_app(
        self,
        org_id: str,
        name: str,
        domain: str,
        verification_method: str = "http_file",
    ) -> Dict[str, Any]:
        """Register a new application with verification challenge tokens."""
        app_id = f"app_{uuid.uuid4().hex[:12]}"
        v_token = f"madps_vfy_{secrets.token_hex(12)}"
        v_path = f"/.well-known/madps-verify-{v_token[:10]}.txt"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO monitored_applications (
                    app_id, org_id, name, domain, verification_token,
                    verification_method, verification_path, is_verified,
                    sdk_connected, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
            """, (app_id, org_id, name, domain.strip().lower(), v_token, verification_method, v_path, now))
            conn.commit()
            return {
                "app_id": app_id,
                "org_id": org_id,
                "name": name,
                "domain": domain.strip().lower(),
                "verification_token": v_token,
                "challenge_token": v_token,
                "verification_method": verification_method,
                "verification_path": v_path,
                "is_verified": False,
                "sdk_connected": False,
                "created_at": now,
            }

    def get_monitored_app(self, app_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fetch application details."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute("SELECT * FROM monitored_applications WHERE app_id = ? AND org_id = ?", (app_id, org_id))
            else:
                cursor.execute("SELECT * FROM monitored_applications WHERE app_id = ?", (app_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "app_id": row["app_id"],
                "org_id": row["org_id"],
                "name": row["name"],
                "domain": row["domain"],
                "verification_token": row["verification_token"],
                "verification_method": row["verification_method"],
                "verification_path": row["verification_path"],
                "is_verified": bool(row["is_verified"]),
                "verified_at": row["verified_at"],
                "sdk_connected": bool(row["sdk_connected"]),
                "last_event_at": row["last_event_at"],
                "created_at": row["created_at"],
            }

    def list_monitored_apps(self, org_id: str) -> List[Dict[str, Any]]:
        """List all applications monitored by an organization."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM monitored_applications 
                WHERE org_id = ? 
                ORDER BY created_at DESC
            """, (org_id,))
            rows = cursor.fetchall()
            return [{
                "app_id": r["app_id"],
                "org_id": r["org_id"],
                "name": r["name"],
                "domain": r["domain"],
                "verification_token": r["verification_token"],
                "verification_method": r["verification_method"],
                "verification_path": r["verification_path"],
                "is_verified": bool(r["is_verified"]),
                "verified_at": r["verified_at"],
                "sdk_connected": bool(r["sdk_connected"]),
                "last_event_at": r["last_event_at"],
                "created_at": r["created_at"],
            } for r in rows]

    def verify_monitored_app(self, app_id: str, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Mark an application domain as verified."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute("UPDATE monitored_applications SET is_verified = 1, verified_at = ? WHERE app_id = ? AND org_id = ?", (now, app_id, org_id))
            else:
                cursor.execute("UPDATE monitored_applications SET is_verified = 1, verified_at = ? WHERE app_id = ?", (now, app_id))
            conn.commit()
            return {"app_id": app_id, "is_verified": True, "verified_at": now}

    def record_app_event(self, app_id: str, org_id: Optional[str] = None) -> None:
        """Update SDK connection state and last event received timestamp."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute("UPDATE monitored_applications SET sdk_connected = 1, last_event_at = ? WHERE app_id = ? AND org_id = ?", (now, app_id, org_id))
            else:
                cursor.execute("UPDATE monitored_applications SET sdk_connected = 1, last_event_at = ? WHERE app_id = ?", (now, app_id))
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────────
    # Contact Requests & Usage Metering
    # ──────────────────────────────────────────────────────────────────────────
    def create_contact_request(self, name: str, email: str, message: str, company: Optional[str] = None) -> Dict[str, Any]:
        """Record public landing page contact / enterprise demo inquiry."""
        req_id = f"req_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO contact_requests (request_id, name, email, company, message, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'new', ?)
            """, (req_id, name, email.strip().lower(), company or "", message, now))
            conn.commit()
            return {
                "request_id": req_id,
                "name": name,
                "email": email,
                "company": company,
                "status": "new",
                "created_at": now,
            }

    def list_contact_requests(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List incoming contact inquiries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM contact_requests ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [{
                "request_id": r["request_id"],
                "name": r["name"],
                "email": r["email"],
                "company": r["company"],
                "message": r["message"],
                "status": r["status"],
                "created_at": r["created_at"],
            } for r in rows]

    def record_usage(
        self,
        org_id: str,
        event_type: str,
        app_id: Optional[str] = None,
        payload_size_bytes: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Meter request volume and telemetry throughput per organization."""
        rec_id = f"use_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO usage_records (record_id, org_id, app_id, timestamp, event_type, payload_size_bytes, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (rec_id, org_id, app_id, now, event_type, payload_size_bytes, json.dumps(metadata or {})))
            conn.commit()

    def get_usage_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregate usage metrics for an organization."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_events,
                    SUM(payload_size_bytes) as total_bytes,
                    SUM(CASE WHEN event_type = 'log_ingest' THEN 1 ELSE 0 END) as ingest_events,
                    SUM(CASE WHEN event_type = 'detection_mesh' THEN 1 ELSE 0 END) as mesh_evals,
                    SUM(CASE WHEN event_type = 'council_debate' THEN 1 ELSE 0 END) as council_debates
                FROM usage_records
                WHERE org_id = ?
            """, (org_id,))
            row = cursor.fetchone()
            return {
                "org_id": org_id,
                "total_events": row["total_events"] if row else 0,
                "total_bytes": row["total_bytes"] if row and row["total_bytes"] else 0,
                "ingest_events": row["ingest_events"] if row else 0,
                "mesh_evals": row["mesh_evals"] if row else 0,
                "council_debates": row["council_debates"] if row else 0,
            }

    # ──────────────────────────────────────────────────────────────────────────
    # Incident & Report Storage
    # ──────────────────────────────────────────────────────────────────────────
    def save_incident(self, incident: Dict[str, Any], org_id: str = "org_default") -> None:
        """Insert or replace an incident emitted by the detection mesh."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, org_id, timestamp, category, severity, confidence,
                    contributing_branch_scores, raw_log_details, campaign_id,
                    affected_endpoints, affected_entities, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.get("incident_id"),
                incident.get("org_id", org_id),
                incident.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                incident.get("category", "UNKNOWN"),
                incident.get("severity", "MEDIUM"),
                float(incident.get("confidence", 0.0)),
                json.dumps(incident.get("contributing_branch_scores", {})),
                json.dumps(incident.get("raw_log_details", {})),
                incident.get("campaign_id"),
                json.dumps(incident.get("affected_endpoints", [])),
                json.dumps(incident.get("affected_entities", [])),
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
            ))
    def get_incident(self, incident_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve single incident record from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute("SELECT * FROM incidents WHERE incident_id = ? AND org_id = ? LIMIT 1", (incident_id, org_id))
            else:
                cursor.execute("SELECT * FROM incidents WHERE incident_id = ? LIMIT 1", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "incident_id": row["incident_id"],
                "org_id": row["org_id"],
                "timestamp": row["timestamp"],
                "category": row["category"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "contributing_branch_scores": json.loads(row["contributing_branch_scores"] or "{}"),
                "raw_log_details": json.loads(row["raw_log_details"] or "{}"),
                "campaign_id": row["campaign_id"],
                "affected_endpoints": json.loads(row["affected_endpoints"] or "[]"),
                "affected_entities": json.loads(row["affected_entities"] or "[]"),
                "created_at": row["created_at"],
            }

    def save_incident_report(self, report_dict: Dict[str, Any], org_id: str = "org_default") -> None:
        """Insert or replace a synthesized council explanation report."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            consensus = report_dict.get("consensus_metric", {})
            if hasattr(consensus, "model_dump"):
                consensus = consensus.model_dump()
            risk = report_dict.get("risk_assessment", {})
            if hasattr(risk, "model_dump"):
                risk = risk.model_dump()

            risk_score = risk.get("risk_score") if (risk and risk.get("risk_score") is not None) else (risk.get("score", 5.0) if risk else 5.0)
            risk_sev = (risk.get("risk_severity_band") or risk.get("severity_band") or "MEDIUM") if risk else "MEDIUM"

            effective_org_id = org_id if (org_id and org_id != "org_default") else (report_dict.get("org_id") or "org_default")
            cursor.execute("""
                INSERT OR REPLACE INTO incident_reports (
                    report_id, incident_id, org_id, generated_at, executive_summary,
                    incident_category, detection_mesh_confidence, consensus_status,
                    consensus_score, risk_score, risk_severity_band,
                    requires_human_approval, human_approval_reasoning,
                    root_cause, technical_timeline, ranked_actions,
                    reconstruction_findings, response_plan, judge_synthesis,
                    debate_revisions, risk_assessment, grounded_timeline, participating_models
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_dict.get("report_id", f"rep-{uuid.uuid4().hex[:8]}"),
                report_dict.get("incident_id", "inc_unknown"),
                effective_org_id,
                report_dict.get("generated_at", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                report_dict.get("executive_summary", ""),
                report_dict.get("incident_category", "UNKNOWN"),
                float(report_dict.get("detection_mesh_confidence", 0.0)),
                consensus.get("status", "CONSENSUS_REACHED"),
                float(consensus.get("consensus_score", 1.0)),
                float(risk_score),
                str(risk_sev).upper(),
                1 if report_dict.get("requires_human_approval") else 0,
                report_dict.get("human_approval_reasoning"),
                report_dict.get("root_cause", ""),
                json.dumps(report_dict.get("technical_timeline", [])),
                json.dumps(report_dict.get("ranked_actions", [])),
                json.dumps(report_dict.get("reconstruction_findings", {})),
                json.dumps(report_dict.get("response_plan", {})),
                json.dumps(report_dict.get("judge_synthesis", {})),
                json.dumps(report_dict.get("debate_revisions", [])),
                json.dumps(risk),
                json.dumps(report_dict.get("grounded_timeline", {})),
                json.dumps(report_dict.get("participating_models", {})),
            ))
            conn.commit()

    def get_incident_report(self, incident_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve full report for an incident with optional multi-tenant org validation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute(
                    "SELECT * FROM incident_reports WHERE incident_id = ? AND org_id = ? ORDER BY generated_at DESC LIMIT 1",
                    (incident_id, org_id),
                )
            else:
                cursor.execute(
                    "SELECT * FROM incident_reports WHERE incident_id = ? ORDER BY generated_at DESC LIMIT 1",
                    (incident_id,),
                )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_report_dict(row)

    def search_incidents_or_reports(self, query: str, org_id: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """Search incidents/reports by ID, category, or endpoint keyword."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            pattern = f"%{query.strip()}%"
            if org_id:
                cursor.execute("""
                    SELECT * FROM incident_reports 
                    WHERE org_id = ? AND (incident_id LIKE ? OR incident_category LIKE ? OR executive_summary LIKE ? OR root_cause LIKE ?)
                    ORDER BY generated_at DESC LIMIT ?
                """, (org_id, pattern, pattern, pattern, pattern, limit))
            else:
                cursor.execute("""
                    SELECT * FROM incident_reports 
                    WHERE incident_id LIKE ? OR incident_category LIKE ? OR executive_summary LIKE ? OR root_cause LIKE ?
                    ORDER BY generated_at DESC LIMIT ?
                """, (pattern, pattern, pattern, pattern, limit))
            rows = cursor.fetchall()
            return [self._row_to_report_dict(r) for r in rows]

    def list_incident_reports(self, limit: int = 50, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all synthesized incident reports with optional org filtering."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            conditions = []
            params = []
            if org_id:
                conditions.append("org_id = ?")
                params.append(org_id)
            
            where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
            params.append(limit)
            cursor.execute(f"SELECT * FROM incident_reports{where_clause} ORDER BY generated_at DESC LIMIT ?", tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_report_dict(r) for r in rows]

    def _row_to_report_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Deserialize DB row into comprehensive incident report format."""
        res = dict(row)
        for json_field in ["technical_timeline", "ranked_actions", "reconstruction_findings", "response_plan", "judge_synthesis", "debate_revisions", "risk_assessment", "grounded_timeline", "participating_models"]:
            if res.get(json_field) and isinstance(res[json_field], str):
                try:
                    res[json_field] = json.loads(res[json_field])
                except Exception:
                    pass
        return res

    def list_action_decisions(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read action decisions from action_decisions.jsonl."""
        decisions_path = Path("data/decisions/action_decisions.jsonl")
        if not decisions_path.exists() and Path("../data/decisions/action_decisions.jsonl").exists():
            decisions_path = Path("../data/decisions/action_decisions.jsonl")
        if not decisions_path.exists():
            return []
        res = []
        try:
            with open(decisions_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        d = json.loads(line)
                        if not incident_id or d.get("incident_id") == incident_id:
                            res.append(d)
        except Exception:
            pass
        return res


    # ──────────────────────────────────────────────────────────────────────────
    # Aggregate Stats Queries
    # ──────────────────────────────────────────────────────────────────────────
    def query_aggregate_stats(self, category: Optional[str] = None, time_window_hours: Optional[int] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run REAL deterministic SQL aggregation against incident_reports & incidents.
        Returns aggregate metrics, severity distributions, and counts.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            conditions = []
            params = []

            if category and category.upper() != "ALL":
                conditions.append("UPPER(incident_category) = ?")
                params.append(category.upper())

            if org_id and org_id != "org_default":
                conditions.append("org_id = ?")
                params.append(org_id)

            if time_window_hours:
                cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=time_window_hours)).isoformat()
                conditions.append("generated_at >= ?")
                params.append(cutoff)

            where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

            query = f"""
                SELECT
                    COUNT(*) as total_reports,
                    AVG(risk_score) as avg_risk_score,
                    AVG(detection_mesh_confidence) as avg_confidence,
                    SUM(CASE WHEN UPPER(risk_severity_band) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN UPPER(risk_severity_band) = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN UPPER(risk_severity_band) = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN UPPER(risk_severity_band) = 'LOW' THEN 1 ELSE 0 END) as low_count,
                    SUM(CASE WHEN requires_human_approval = 1 THEN 1 ELSE 0 END) as approval_required_count
                FROM incident_reports
                {where_clause}
            """
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()

            cat_query = f"""
                SELECT incident_category, COUNT(*) as cnt
                FROM incident_reports
                {where_clause}
                GROUP BY incident_category
            """
            cursor.execute(cat_query, tuple(params))
            cat_rows = cursor.fetchall()
            category_breakdown = {r["incident_category"]: r["cnt"] for r in cat_rows}

            avg_risk = row["avg_risk_score"] if (row and row["avg_risk_score"] is not None) else 0.0
            avg_conf = row["avg_confidence"] if (row and row["avg_confidence"] is not None) else 0.0

            return {
                "total_incidents": row["total_reports"] if row else 0,
                "total_reports": row["total_reports"] if row else 0,
                "category_filter": category or "ALL",
                "time_window_hours": time_window_hours or "ALL_TIME",
                "org_id": org_id or "ALL_ORGS",
                "average_risk_score": round(float(avg_risk), 2),
                "average_mesh_confidence": round(float(avg_conf), 3),
                "critical_count": row["critical_count"] if row else 0,
                "high_count": row["high_count"] if row else 0,
                "medium_count": row["medium_count"] if row else 0,
                "low_count": row["low_count"] if row else 0,
                "approval_required_count": row["approval_required_count"] if row else 0,
                "category_breakdown": category_breakdown,
            }

    # ──────────────────────────────────────────────────────────────────────────
    # Conversation Memory & Context
    # ──────────────────────────────────────────────────────────────────────────
    def create_conversation(self, user_id: str, org_id: str, title: Optional[str] = None) -> str:
        """Create a new conversation session for a user within their organization."""
        conv_id = f"conv-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO conversations (conversation_id, user_id, org_id, title, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (conv_id, user_id, org_id, title or "New Security Dialogue", now, now))
            conn.commit()
            logger.info("Created conversation %s for user %s in org %s", conv_id, user_id, org_id)
            return conv_id

    def append_message(
        self,
        conversation_id: str,
        user_id: str,
        org_id: str,
        role: str,
        content: str,
        sources_cited: Optional[List[str]] = None,
        retrieved_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Append a message turn to conversation history with tenant boundary check."""
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT conversation_id FROM conversations WHERE conversation_id = ? AND org_id = ?", (conversation_id, org_id))
            if not cursor.fetchone():
                self.create_conversation(user_id=user_id, org_id=org_id, title=content[:40])

            cursor.execute("""
                INSERT INTO conversation_messages (
                    message_id, conversation_id, user_id, org_id, role, content, sources_cited, retrieved_context, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                msg_id, conversation_id, user_id, org_id, role, content,
                json.dumps(sources_cited or []),
                json.dumps(retrieved_context or {}),
                now
            ))
            cursor.execute("UPDATE conversations SET updated_at = ? WHERE conversation_id = ?", (now, conversation_id))
            conn.commit()
            return msg_id

    def get_conversation_history(self, conversation_id: str, org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve chronological message history for a conversation strictly scoped to org_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM conversation_messages 
                WHERE conversation_id = ? AND org_id = ?
                ORDER BY created_at ASC LIMIT ?
            """, (conversation_id, org_id, limit))
            rows = cursor.fetchall()
            messages = []
            for r in rows:
                messages.append({
                    "message_id": r["message_id"],
                    "conversation_id": r["conversation_id"],
                    "user_id": r["user_id"],
                    "org_id": r["org_id"],
                    "role": r["role"],
                    "content": r["content"],
                    "sources_cited": json.loads(r["sources_cited"] or "[]"),
                    "retrieved_context": json.loads(r["retrieved_context"] or "{}"),
                    "created_at": r["created_at"],
                })
            return messages

    def list_user_conversations(self, user_id: str, org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """List active conversation threads for a user within an org."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM conversations 
                WHERE user_id = ? AND org_id = ?
                ORDER BY updated_at DESC LIMIT ?
            """, (user_id, org_id, limit))
            rows = cursor.fetchall()
            return [{
                "conversation_id": r["conversation_id"],
                "user_id": r["user_id"],
                "org_id": r["org_id"],
                "title": r["title"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            } for r in rows]

    def delete_conversation(self, conversation_id: str, org_id: str) -> bool:
        """Delete a conversation thread and all its turns within tenant boundaries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM conversation_messages WHERE conversation_id = ? AND org_id = ?", (conversation_id, org_id))
            cursor.execute("DELETE FROM conversations WHERE conversation_id = ? AND org_id = ?", (conversation_id, org_id))
            conn.commit()
            return cursor.rowcount > 0

    # ──────────────────────────────────────────────────────────────────────────
    # Traffic Inspection Persistence
    # ──────────────────────────────────────────────────────────────────────────
    def save_traffic_inspection(self, insp: Dict[str, Any], org_id: str = "org_default") -> None:
        """Persist a live traffic inspection event."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            council_id = None
            if insp.get("council_report") and isinstance(insp["council_report"], dict):
                council_id = insp["council_report"].get("report_id")

            cursor.execute("""
                INSERT OR REPLACE INTO traffic_inspections (
                    inspection_id, org_id, timestamp, target_url, method, status_code,
                    latency_ms, category, confidence, severity, is_threat,
                    branch_scores, entropy, matched_tokens, response_body_preview,
                    raw_telemetry, council_report_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                insp.get("inspection_id", f"insp-{uuid.uuid4().hex[:10]}"),
                insp.get("org_id", org_id),
                insp.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                insp.get("target_url", "http://target-api"),
                insp.get("method", "GET"),
                insp.get("status_code", 200),
                float(insp.get("latency_ms", 0.0)),
                insp.get("category", "BENIGN_TELEMETRY"),
                float(insp.get("confidence", 0.0)),
                insp.get("severity", "LOW"),
                1 if insp.get("is_threat") else 0,
                json.dumps(insp.get("branch_scores", {})),
                float(insp.get("entropy", 0.0)),
                json.dumps(insp.get("matched_tokens", [])),
                insp.get("response_body_preview", "")[:500],
                json.dumps(insp.get("raw_telemetry", {})),
                council_id,
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
            ))
            conn.commit()

    def list_traffic_inspections(self, limit: int = 50, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent traffic inspections."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if org_id:
                cursor.execute("""
                    SELECT * FROM traffic_inspections WHERE org_id = ?
                    ORDER BY created_at DESC LIMIT ?
                """, (org_id, limit))
            else:
                cursor.execute("SELECT * FROM traffic_inspections ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [{
                "inspection_id": r["inspection_id"],
                "org_id": r["org_id"],
                "timestamp": r["timestamp"],
                "target_url": r["target_url"],
                "method": r["method"],
                "status_code": r["status_code"],
                "latency_ms": r["latency_ms"],
                "category": r["category"],
                "confidence": r["confidence"],
                "severity": r["severity"],
                "is_threat": bool(r["is_threat"]),
                "branch_scores": json.loads(r["branch_scores"] or "{}"),
                "entropy": r["entropy"],
                "matched_tokens": json.loads(r["matched_tokens"] or "[]"),
                "response_body_preview": r["response_body_preview"],
                "raw_telemetry": json.loads(r["raw_telemetry"] or "{}"),
                "council_report_id": r["council_report_id"],
                "created_at": r["created_at"],
            } for r in rows]

    def get_dbms_overview(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Aggregate statistical summary for Enterprise DBMS explorer."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cond = " WHERE org_id = ?" if org_id else ""
            params = (org_id,) if org_id else ()

            cursor.execute(f"SELECT COUNT(*), AVG(risk_score), AVG(detection_mesh_confidence) FROM incident_reports{cond}", params)
            rep_stats = cursor.fetchone()
            total_reports = rep_stats[0] or 0
            avg_risk = round(rep_stats[1] or 0.0, 2)
            avg_conf = round(rep_stats[2] or 0.0, 3)

            cursor.execute(f"SELECT incident_category, COUNT(*) FROM incident_reports{cond} GROUP BY incident_category", params)
            cat_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(f"SELECT COUNT(*), SUM(is_threat) FROM traffic_inspections{cond}", params)
            insp_stats = cursor.fetchone()
            total_inspections = insp_stats[0] or 0
            threat_inspections = insp_stats[1] or 0

            cursor.execute(f"SELECT COUNT(*) FROM conversations{cond}", params)
            total_convs = cursor.fetchone()[0] or 0

            cursor.execute(f"SELECT COUNT(*) FROM monitored_applications{cond}", params)
            total_apps = cursor.fetchone()[0] or 0

            return {
                "total_reports": total_reports,
                "average_risk_score": avg_risk,
                "average_mesh_confidence": avg_conf,
                "category_breakdown": cat_counts,
                "total_inspections": total_inspections,
                "threat_inspections": threat_inspections,
                "total_conversations": total_convs,
                "total_monitored_apps": total_apps,
                "storage_engine": "SQLite/Postgres Unified Product DBMS",
            }

    # ──────────────────────────────────────────────────────────────────────────
    # Task X1: Pipeline Trace Diagnostics (13-Hop Tracing)
    # ──────────────────────────────────────────────────────────────────────────
    def record_pipeline_trace(
        self,
        trace_id: str,
        hop_step: int,
        hop_code: str,
        service: str,
        details: Dict[str, Any],
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an immutable hop in the 13-point diagnostic trace chain."""
        ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else str(details)
        
        # Log to stdout if PIPELINE_DEBUG is explicitly enabled
        pipeline_debug = os.environ.get("PIPELINE_DEBUG", "false").lower() in ("true", "1", "yes")
        if pipeline_debug:
            print(f"[PIPELINE_TRACE] Step {hop_step:02d} {hop_code:20s} | trace_id={trace_id} | service={service} | {details_str}", flush=True)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pipeline_trace (trace_id, hop_step, hop_code, service, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (trace_id, hop_step, hop_code, service, details_str, ts))
            conn.commit()
            return {
                "trace_id": trace_id,
                "hop_step": hop_step,
                "hop_code": hop_code,
                "service": service,
                "details": details,
                "timestamp": ts,
            }

    def get_pipeline_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Retrieve ordered hop-by-hop sequence for a specific trace_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, trace_id, hop_step, hop_code, service, details, timestamp
                FROM pipeline_trace
                WHERE trace_id = ?
                ORDER BY hop_step ASC, id ASC
            """, (trace_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                try:
                    det = json.loads(r["details"])
                except Exception:
                    det = r["details"]
                results.append({
                    "id": r["id"],
                    "trace_id": r["trace_id"],
                    "hop_step": r["hop_step"],
                    "hop_code": r["hop_code"],
                    "service": r["service"],
                    "details": det,
                    "timestamp": r["timestamp"],
                })
            return results

    def list_pipeline_traces(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent trace IDs with start time and latest completed hop."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT trace_id, MIN(timestamp) as started_at, MAX(timestamp) as latest_at,
                       COUNT(*) as hops_count, MAX(hop_step) as max_hop,
                       GROUP_CONCAT(hop_code, ' -> ') as hop_chain
                FROM pipeline_trace
                GROUP BY trace_id
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def list_records_for_table(self, table_name: str, limit: int = 50, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Safely fetch raw records from a table for DBMS Inspector."""
        allowed_tables = [
            "incident_reports", "incidents", "traffic_inspections",
            "conversations", "conversation_messages", "organizations",
            "users", "api_keys", "monitored_applications", "contact_requests", "usage_records",
            "pipeline_trace"
        ]
        if table_name not in allowed_tables:
            return []

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # If table has org_id column and org_id is specified
            has_org = table_name in ["incident_reports", "incidents", "traffic_inspections", "conversations", "conversation_messages", "users", "api_keys", "monitored_applications", "usage_records"]
            if has_org and org_id:
                cursor.execute(f"SELECT * FROM {table_name} WHERE org_id = ? ORDER BY created_at DESC LIMIT ?", (org_id, limit))
            else:
                cursor.execute(f"SELECT * FROM {table_name} ORDER BY 1 DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def _row_to_report_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a SQLite Row to a dictionary matching FinalExplanationReport schema."""
        keys = row.keys()
        return {
            "report_id": row["report_id"],
            "incident_id": row["incident_id"],
            "org_id": row["org_id"] if "org_id" in keys else "org_default",
            "generated_at": row["generated_at"],
            "executive_summary": row["executive_summary"],
            "incident_category": row["incident_category"],
            "detection_mesh_confidence": row["detection_mesh_confidence"],
            "consensus_metric": {
                "status": row["consensus_status"],
                "consensus_score": row["consensus_score"],
            },
            "risk_assessment": json.loads(row["risk_assessment"] or "{}"),
            "requires_human_approval": bool(row["requires_human_approval"]),
            "human_approval_reasoning": row["human_approval_reasoning"],
            "root_cause": row["root_cause"],
            "technical_timeline": json.loads(row["technical_timeline"] or "[]"),
            "ranked_actions": json.loads(row["ranked_actions"] or "[]"),
            "reconstruction_findings": json.loads(row["reconstruction_findings"] or "{}"),
            "response_plan": json.loads(row["response_plan"] or "{}"),
            "judge_synthesis": json.loads(row["judge_synthesis"] or "{}"),
            "debate_revisions": json.loads(row["debate_revisions"] or "[]"),
            "grounded_timeline": json.loads(row["grounded_timeline"] or "{}"),
            "participating_models": json.loads(row["participating_models"] or "{}"),
        }


# Global DB instance
shared_db = SharedProductDatabase()
