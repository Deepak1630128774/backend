import sqlite3

from .services.acl import ensure_user_default_permissions
from .services.security import hash_password
from .settings import (
    BOOTSTRAP_OWNER_EMAIL,
    BOOTSTRAP_OWNER_NAME,
    BOOTSTRAP_OWNER_PASSWORD,
    DB_PATH,
    FUEL_DB_PATH,
    PROJECT_DB_PATH,
    STRATEGY_DB_PATH,
)

MODULE_SUB_ENTITIES = {
    "fuel": ["inventory_rows", "yearly_data_rows", "reduction_targets"],
    "co2": ["input_rows", "output_rows", "costing_rows"],
    "macc": ["calculations", "evaluation_options", "evaluation_results"],
    "strategy": ["macc_selections", "portfolio_snapshots"],
}


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return bool(row)


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def _migrate_co2_project_name_index(conn: sqlite3.Connection) -> None:
    conn.execute("DROP INDEX IF EXISTS idx_unique_project_name")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_project_name
        ON projects(organization, project_name)
        WHERE project_name IS NOT NULL AND trim(project_name) != ''
        """
    )


def _migrate_strategy_portfolios_name_scope(conn: sqlite3.Connection) -> None:
    table_sql_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'strategy_portfolios'"
    ).fetchone()
    table_sql = str(table_sql_row[0] if table_sql_row else "")
    if "NAME TEXT UNIQUE" in table_sql.upper():
        conn.execute("ALTER TABLE strategy_portfolios RENAME TO strategy_portfolios_legacy")
        conn.execute(
            """
            CREATE TABLE strategy_portfolios (
                id TEXT PRIMARY KEY,
                name TEXT,
                organization TEXT,
                sector TEXT,
                baseline_calc_id TEXT,
                selected_macc_projects TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            INSERT INTO strategy_portfolios (id, name, organization, sector, baseline_calc_id, selected_macc_projects, created_at, updated_at)
            SELECT id, name, organization, sector, baseline_calc_id, selected_macc_projects, created_at, updated_at
            FROM strategy_portfolios_legacy
            """
        )
        conn.execute("DROP TABLE strategy_portfolios_legacy")

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_strategy_portfolios_org_name
        ON strategy_portfolios(organization, name)
        WHERE name IS NOT NULL AND trim(name) != ''
        """
    )


def _dedupe_permissions(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id, user_id, module_id, project_id, sub_entity_id
        FROM permissions
        ORDER BY updated_at DESC, id DESC
        """
    ).fetchall()
    seen: set[tuple[int, int | None, int | None, int | None]] = set()
    keep_ids: set[int] = set()
    for row in rows:
        key = (int(row[1]), row[2], row[3], row[4])
        if key in seen:
            continue
        seen.add(key)
        keep_ids.add(int(row[0]))
    if not rows:
        return
    all_ids = {int(row[0]) for row in rows}
    delete_ids = sorted(all_ids - keep_ids)
    if delete_ids:
        placeholders = ",".join("?" for _ in delete_ids)
        conn.execute(f"DELETE FROM permissions WHERE id IN ({placeholders})", tuple(delete_ids))


def _backfill_acl_projects(
    strategy_conn: sqlite3.Connection,
    *,
    owner_user_id: int,
) -> None:
    module_ids = {
        row[0]: int(row[1])
        for row in strategy_conn.execute("SELECT module_key, id FROM modules").fetchall()
    }
    org_by_name = {
        str(row[0]).strip().lower(): int(row[1])
        for row in strategy_conn.execute("SELECT name, id FROM organizations").fetchall()
        if row[0]
    }

    fuel_conn = sqlite3.connect(str(FUEL_DB_PATH))
    fuel_rows = fuel_conn.execute(
        "SELECT unique_code, org_name FROM calculations WHERE unique_code IS NOT NULL AND unique_code != ''"
    ).fetchall()
    fuel_conn.close()

    co2_conn = sqlite3.connect(str(PROJECT_DB_PATH))
    co2_rows = co2_conn.execute(
        "SELECT project_code, project_name, organization FROM projects WHERE project_code IS NOT NULL AND project_code != ''"
    ).fetchall()
    co2_conn.close()

    npv_conn = sqlite3.connect(str(DB_PATH))
    macc_rows = npv_conn.execute(
        "SELECT id, project_name, organization FROM npv_projects WHERE id IS NOT NULL AND id != ''"
    ).fetchall()
    npv_conn.close()

    strategy_rows = strategy_conn.execute(
        "SELECT id, name, organization FROM strategy_portfolios WHERE id IS NOT NULL AND id != ''"
    ).fetchall()

    def upsert_project(module_key: str, external_id: str, name: str, org_name: str) -> None:
        if module_key not in module_ids:
            return
        org_id = org_by_name.get(str(org_name or "").strip().lower())
        strategy_conn.execute(
            """
            INSERT OR IGNORE INTO projects
            (module_id, external_project_id, project_name, owner_user_id, created_by_user_id, organization_id, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                module_ids[module_key],
                external_id,
                name or external_id,
                owner_user_id,
                owner_user_id,
                org_id,
            ),
        )
        project_row = strategy_conn.execute(
            "SELECT id FROM projects WHERE module_id = ? AND external_project_id = ?",
            (module_ids[module_key], external_id),
        ).fetchone()
        if not project_row:
            return
        project_id = int(project_row[0])
        strategy_conn.execute(
            """
            INSERT OR IGNORE INTO permissions
            (user_id, module_id, project_id, sub_entity_id, can_view, can_create, can_edit, can_delete, can_approve, can_assign, can_evaluate, granted_by_user_id, created_at, updated_at)
            VALUES (?, ?, ?, NULL, 1, 1, 1, 1, 1, 1, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (owner_user_id, module_ids[module_key], project_id, owner_user_id),
        )
        for sub_key in MODULE_SUB_ENTITIES.get(module_key, []):
            strategy_conn.execute(
                """
                INSERT OR IGNORE INTO sub_entities
                (project_id, sub_entity_key, external_sub_entity_id, sub_entity_name, created_at, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (project_id, sub_key, sub_key, sub_key.replace("_", " ").title()),
            )

    for unique_code, org_name in fuel_rows:
        upsert_project("fuel", str(unique_code), str(unique_code), str(org_name or ""))
    for project_code, project_name, org_name in co2_rows:
        upsert_project("co2", str(project_code), str(project_name or project_code), str(org_name or ""))
    for project_id, project_name, org_name in macc_rows:
        upsert_project("macc", str(project_id), str(project_name or project_id), str(org_name or ""))
    for portfolio_id, portfolio_name, org_name in strategy_rows:
        upsert_project("strategy", str(portfolio_id), str(portfolio_name or portfolio_id), str(org_name or ""))


def init_databases() -> None:
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS npv_projects (
            id TEXT PRIMARY KEY,
            organization TEXT,
            entity_name TEXT,
            unit_name TEXT,
            project_name TEXT,
            base_year TEXT,
            target_year TEXT,
            implementation_date TEXT,
            life_span TEXT,
            project_owner TEXT,
            initiative TEXT,
            industry TEXT,
            country TEXT,
            year TEXT,
            material_energy_data TEXT,
            option1_data TEXT,
            option2_data TEXT,
            result TEXT,
            npv1 REAL,
            npv2 REAL,
            mac REAL,
            total_co2_diff REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(FUEL_DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS calculations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_code TEXT UNIQUE,
            org_name TEXT,
            entity_name TEXT,
            unit_name TEXT,
            project_owner TEXT,
            sector TEXT,
            baseline_year INTEGER,
            previous_year INTEGER,
            target_year INTEGER,
            baseline_production REAL,
            previous_year_production REAL,
            growth_rate REAL,
            target_production REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS materials_baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            calculation_id INTEGER,
            row_num INTEGER,
            scope TEXT,
            name TEXT,
            uom TEXT,
            quantity REAL,
            ef REAL,
            emission REAL,
            energy_factor REAL,
            energy_factor_uom TEXT,
            energy REAL,
            FOREIGN KEY (calculation_id) REFERENCES calculations(id) ON DELETE CASCADE
        )
        """
    )
    _ensure_column(conn, "calculations", "entity_name", "TEXT")
    _ensure_column(conn, "calculations", "unit_name", "TEXT")
    _ensure_column(conn, "calculations", "project_owner", "TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS emission_reductions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            calculation_id INTEGER,
            scope TEXT CHECK(scope IN ('Scope 1', 'Scope 2', 'Scope 3')),
            reduction_pct REAL,
            FOREIGN KEY (calculation_id) REFERENCES calculations(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS base_value_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            calculation_id INTEGER,
            scope TEXT CHECK(scope IN ('Scope 1', 'Scope 2', 'Scope 3')),
            value REAL,
            FOREIGN KEY (calculation_id) REFERENCES calculations(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fuel_yearly_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_code TEXT,
            year_number INTEGER,
            row_num INTEGER,
            material TEXT,
            scope TEXT,
            uom TEXT,
            quantity REAL,
            ef REAL,
            emission REAL,
            energy_factor REAL,
            energy_factor_uom TEXT,
            energy REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(PROJECT_DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_code TEXT UNIQUE,
            organization TEXT,
            entity_name TEXT,
            unit_name TEXT,
            project_name TEXT,
            base_year TEXT,
            target_year TEXT,
            implementation_date TEXT,
            capex TEXT,
            life_span TEXT,
            project_owner TEXT,
            input_data TEXT,
            output_data TEXT,
            costing_data TEXT,
            amp_before REAL,
            amp_after REAL,
            amp_uom TEXT,
            emission_results TEXT,
            costing_results TEXT,
            calculation_method TEXT,
            status TEXT DEFAULT 'Planned',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    _ensure_column(conn, "projects", "status", "TEXT DEFAULT 'Planned'")
    _migrate_co2_project_name_index(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS project_actuals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_code TEXT,
            section_type TEXT,
            material_name TEXT,
            row_index INTEGER,
            year_number INTEGER,
            absolute_value REAL,
            specific_value REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_code) REFERENCES projects(project_code)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS amp_actuals_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_code TEXT,
            year_number INTEGER,
            amp_value REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_code) REFERENCES projects(project_code)
        )
        """
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(STRATEGY_DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strategy_portfolios (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            organization TEXT,
            sector TEXT,
            baseline_calc_id TEXT,
            selected_macc_projects TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    _migrate_strategy_portfolios_name_scope(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            purchaser_email TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    _ensure_column(conn, "organizations", "slug", "TEXT")
    _ensure_column(conn, "organizations", "status", "TEXT DEFAULT 'active'")
    _ensure_column(conn, "organizations", "approval_status", "TEXT DEFAULT 'approved'")
    _ensure_column(conn, "organizations", "status_note", "TEXT")
    _ensure_column(conn, "organizations", "approved_by_user_id", "INTEGER")
    _ensure_column(conn, "organizations", "approved_at", "TIMESTAMP")
    _ensure_column(conn, "organizations", "updated_at", "TIMESTAMP")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_boundaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER,
            organization_name TEXT,
            subsidiary_name TEXT,
            associate_name TEXT,
            manufacturing_unit TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL UNIQUE,
            is_primary INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER,
            full_name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            is_active INTEGER DEFAULT 1,
            is_approved INTEGER DEFAULT 0,
            created_by_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
        """
    )
    _ensure_column(conn, "users", "signup_type", "TEXT DEFAULT 'legacy'")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            membership_role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            invited_by_user_id INTEGER,
            approved_by_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization_id, user_id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (invited_by_user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            font_size TEXT DEFAULT 'medium',
            color_theme TEXT DEFAULT 'emerald',
            dark_mode INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_name TEXT,
            full_name TEXT,
            email TEXT,
            password_hash TEXT,
            purchase_reference TEXT,
            status TEXT DEFAULT 'pending',
            reviewed_by_user_id INTEGER,
            review_note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS signup_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signup_type TEXT NOT NULL,
            organization_name TEXT,
            organization_slug TEXT,
            organization_id INTEGER,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            purchase_reference TEXT,
            requested_role TEXT NOT NULL DEFAULT 'org_user',
            otp_code_hash TEXT NOT NULL,
            otp_expires_at TIMESTAMP NOT NULL,
            otp_verified_at TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'otp_pending',
            review_note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS email_otp_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL,
            reference_type TEXT,
            reference_id TEXT,
            otp_hash TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            is_used INTEGER DEFAULT 0,
            attempt_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token_hash TEXT,
            expires_at TIMESTAMP,
            is_used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_otp_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            code_hash TEXT,
            expires_at TIMESTAMP,
            is_used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            inviter_user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT,
            role TEXT NOT NULL DEFAULT 'org_user',
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            accepted_user_id INTEGER,
            accepted_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (inviter_user_id) REFERENCES users(id),
            FOREIGN KEY (accepted_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_member_signup_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            requested_role TEXT NOT NULL DEFAULT 'org_user',
            otp_code_hash TEXT NOT NULL,
            otp_expires_at TIMESTAMP NOT NULL,
            otp_verified_at TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'otp_pending',
            review_note TEXT,
            reviewed_by_user_id INTEGER,
            reviewed_at TIMESTAMP,
            approved_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id),
            FOREIGN KEY (approved_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS normal_user_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            reviewed_by_user_id INTEGER,
            reviewed_at TIMESTAMP,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_status_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reviewed_by_user_id INTEGER,
            reviewed_at TIMESTAMP,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS owners (
            user_id INTEGER PRIMARY KEY,
            created_by_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            page_key TEXT,
            button_key TEXT,
            is_allowed INTEGER DEFAULT 1,
            updated_by_user_id INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS project_status_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_code TEXT,
            status TEXT,
            comment TEXT,
            updated_by_email TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reminder_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            project_code TEXT,
            reminder_type TEXT,
            due_date TEXT,
            sent_at TIMESTAMP,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_key TEXT UNIQUE,
            module_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_id INTEGER NOT NULL,
            external_project_id TEXT NOT NULL,
            project_name TEXT,
            owner_user_id INTEGER NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            organization_id INTEGER,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(module_id, external_project_id),
            FOREIGN KEY (module_id) REFERENCES modules(id),
            FOREIGN KEY (owner_user_id) REFERENCES users(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sub_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            sub_entity_key TEXT NOT NULL,
            external_sub_entity_id TEXT NOT NULL,
            sub_entity_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(project_id, sub_entity_key, external_sub_entity_id),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            module_id INTEGER,
            project_id INTEGER,
            sub_entity_id INTEGER,
            can_view INTEGER DEFAULT 0,
            can_create INTEGER DEFAULT 0,
            can_edit INTEGER DEFAULT 0,
            can_delete INTEGER DEFAULT 0,
            can_approve INTEGER DEFAULT 0,
            can_assign INTEGER DEFAULT 0,
            can_evaluate INTEGER DEFAULT 0,
            granted_by_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, module_id, project_id, sub_entity_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (module_id) REFERENCES modules(id),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (sub_entity_id) REFERENCES sub_entities(id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by_user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            module_id INTEGER,
            project_id INTEGER,
            sub_entity_id INTEGER,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id),
            FOREIGN KEY (module_id) REFERENCES modules(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (sub_entity_id) REFERENCES sub_entities(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON permissions(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_module_id ON permissions(module_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_project_id ON permissions(project_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_sub_entity_id ON permissions(sub_entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_projects_module_external ON projects(module_id, external_project_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sub_entities_project_key ON sub_entities(project_id, sub_entity_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_domains_subdomain ON organization_domains(subdomain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_organization_domains_org_id ON organization_domains(organization_id)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_memberships_org_user ON organization_memberships(organization_id, user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memberships_user_status ON organization_memberships(user_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_otp_email_purpose ON email_otp_challenges(email, purpose, is_used)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_otp_reference ON email_otp_challenges(reference_type, reference_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_member_signup_requests_org_status ON organization_member_signup_requests(organization_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_member_signup_requests_email_status ON organization_member_signup_requests(email, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_normal_user_approvals_status ON normal_user_approvals(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_status_approvals_org_status ON organization_status_approvals(organization_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signup_requests_email_status ON signup_requests(email, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signup_requests_organization_id ON signup_requests(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_organization_invitations_email_status ON organization_invitations(email, status)")
    conn.execute(
        """
        INSERT OR IGNORE INTO modules (module_key, module_name) VALUES
            ('fuel', 'Fuel & Energy'),
            ('co2', 'CO2 Projects'),
            ('macc', 'MACC'),
            ('strategy', 'Strategy'),
            ('admin', 'Admin Dashboard')
        """
    )
    conn.execute(
        """
        UPDATE organizations
        SET slug = lower(replace(trim(name), ' ', '-'))
        WHERE slug IS NULL AND name IS NOT NULL AND trim(name) != ''
        """
    )
    conn.execute(
        """
        UPDATE organizations
        SET status = CASE WHEN is_active = 1 THEN 'active' ELSE 'inactive' END
        WHERE status IS NULL OR trim(status) = ''
        """
    )
    conn.execute(
        """
        UPDATE organizations
        SET approval_status = CASE WHEN is_active = 1 THEN 'approved' ELSE 'pending' END
        WHERE approval_status IS NULL OR trim(approval_status) = ''
        """
    )
    conn.execute(
        """
        UPDATE organizations
        SET updated_at = CURRENT_TIMESTAMP
        WHERE updated_at IS NULL
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO organization_domains (organization_id, subdomain, is_primary, created_at, updated_at)
        SELECT id, slug, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM organizations
        WHERE slug IS NOT NULL AND trim(slug) != ''
        """
    )
    conn.execute(
        """
        UPDATE users
        SET signup_type = CASE
            WHEN organization_id IS NULL THEN 'normal_user'
            WHEN role IN ('buyer_admin', 'owner', 'super_admin') THEN 'organization_admin'
            ELSE 'organization_user'
        END
        WHERE signup_type IS NULL OR trim(signup_type) = ''
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO organization_memberships
        (organization_id, user_id, membership_role, status, invited_by_user_id, approved_by_user_id, created_at, updated_at)
        SELECT
            u.organization_id,
            u.id,
            CASE WHEN lower(trim(u.role)) = 'buyer_admin' THEN 'org_admin' ELSE 'org_user' END,
            CASE WHEN u.is_active = 1 AND u.is_approved = 1 AND COALESCE(o.approval_status, 'approved') = 'approved' THEN 'active' ELSE 'pending' END,
            u.created_by_user_id,
            o.approved_by_user_id,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        FROM users u
        LEFT JOIN organizations o ON o.id = u.organization_id
        WHERE u.organization_id IS NOT NULL
        """
    )
    conn.execute(
        """
        UPDATE organization_memberships
        SET status = CASE
            WHEN EXISTS (
                SELECT 1
                FROM users u
                JOIN organizations o ON o.id = organization_memberships.organization_id
                WHERE u.id = organization_memberships.user_id
                  AND u.is_active = 1
                  AND u.is_approved = 1
                  AND COALESCE(o.approval_status, 'approved') = 'approved'
            ) THEN 'active'
            ELSE 'pending'
        END,
        updated_at = CURRENT_TIMESTAMP
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO owners (user_id, created_by_user_id, created_at)
        SELECT id, created_by_user_id, CURRENT_TIMESTAMP
        FROM users
        WHERE lower(trim(role)) IN ('owner', 'super_admin')
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO normal_user_approvals
        (user_id, status, reviewed_by_user_id, reviewed_at, note, created_at, updated_at)
        SELECT
            u.id,
            CASE WHEN u.is_approved = 1 THEN 'approved' ELSE 'pending' END,
            NULL,
            CASE WHEN u.is_approved = 1 THEN CURRENT_TIMESTAMP ELSE NULL END,
            NULL,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        FROM users u
        WHERE u.organization_id IS NULL
          AND lower(trim(u.role)) = 'org_user'
        """
    )
    conn.execute(
        """
        INSERT INTO organization_status_approvals
        (organization_id, status, reviewed_by_user_id, reviewed_at, note, created_at, updated_at)
        SELECT o.id, o.approval_status, o.approved_by_user_id, o.approved_at, o.status_note, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM organizations o
        WHERE NOT EXISTS (
            SELECT 1
            FROM organization_status_approvals osa
            WHERE osa.organization_id = o.id
        )
        """
    )
    if _table_exists(conn, "user_permissions"):
        # One-time migration from legacy page/button ACL into module-level permissions.
        legacy_rows = conn.execute(
            """
            SELECT up.user_id, lower(trim(up.page_key)) AS page_key, lower(trim(up.button_key)) AS button_key, up.is_allowed
            FROM user_permissions up
            """
        ).fetchall()
        module_map = {row[0]: row[1] for row in conn.execute("SELECT module_key, id FROM modules").fetchall()}
        for row in legacy_rows:
            module_key = row[1]
            if module_key not in module_map:
                continue
            module_id = module_map[module_key]
            can_view = 1 if row[3] else 0
            can_create = 1 if row[2] in {"save", "create", "yearly_save", "tracking_save"} and row[3] else 0
            can_edit = can_create
            can_delete = 1 if row[2] == "delete" and row[3] else 0
            can_approve = 1 if row[2] in {"status", "approve"} and row[3] else 0
            can_assign = 1 if row[2] in {"assign", "permissions"} and row[3] else 0
            can_evaluate = 1 if row[2] in {"evaluate", "compute", "analyze"} and row[3] else 0
            conn.execute(
                """
                INSERT INTO permissions
                (user_id, module_id, project_id, sub_entity_id, can_view, can_create, can_edit, can_delete, can_approve, can_assign, can_evaluate, granted_by_user_id, created_at, updated_at)
                VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id, module_id, project_id, sub_entity_id) DO UPDATE SET
                    can_view = MAX(can_view, excluded.can_view),
                    can_create = MAX(can_create, excluded.can_create),
                    can_edit = MAX(can_edit, excluded.can_edit),
                    can_delete = MAX(can_delete, excluded.can_delete),
                    can_approve = MAX(can_approve, excluded.can_approve),
                    can_assign = MAX(can_assign, excluded.can_assign),
                    can_evaluate = MAX(can_evaluate, excluded.can_evaluate),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    row[0],
                    module_id,
                    can_view,
                    can_create,
                    can_edit,
                    can_delete,
                    can_approve,
                    can_assign,
                    can_evaluate,
                ),
            )
    if BOOTSTRAP_OWNER_EMAIL and BOOTSTRAP_OWNER_PASSWORD:
        existing_owner = conn.execute(
            "SELECT id, role, password_hash FROM users WHERE lower(email) = ?",
            (BOOTSTRAP_OWNER_EMAIL.lower(),),
        ).fetchone()
        if not existing_owner:
            conn.execute(
                """
                INSERT INTO users
                (organization_id, full_name, email, password_hash, role, is_active, is_approved, created_at, updated_at)
                VALUES (NULL, ?, ?, ?, 'super_admin', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    BOOTSTRAP_OWNER_NAME,
                    BOOTSTRAP_OWNER_EMAIL.lower(),
                    hash_password(BOOTSTRAP_OWNER_PASSWORD),
                ),
            )
        elif existing_owner[1] != "super_admin":
            conn.execute(
                """
                UPDATE users
                SET role = 'super_admin',
                    is_active = 1,
                    is_approved = 1,
                    full_name = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    BOOTSTRAP_OWNER_NAME,
                    existing_owner[0],
                ),
            )
        else:
            conn.execute(
                """
                UPDATE users
                SET full_name = ?,
                    is_active = 1,
                    is_approved = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    BOOTSTRAP_OWNER_NAME,
                    existing_owner[0],
                ),
            )
    conn.execute(
        """
        UPDATE users
        SET role = 'super_admin',
            is_active = 1,
            is_approved = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE lower(email) = 'deepakbagam001@gmail.com'
        """
    )
    owner_row = conn.execute("SELECT id FROM users WHERE role IN ('owner', 'super_admin')").fetchone()
    if owner_row:
        owner_id = int(owner_row[0])
        modules = conn.execute("SELECT id FROM modules").fetchall()
        for module in modules:
            conn.execute(
                """
                INSERT INTO permissions
                (user_id, module_id, project_id, sub_entity_id, can_view, can_create, can_edit, can_delete, can_approve, can_assign, can_evaluate, granted_by_user_id, created_at, updated_at)
                VALUES (?, ?, NULL, NULL, 1, 1, 1, 1, 1, 1, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id, module_id, project_id, sub_entity_id)
                DO UPDATE SET
                    can_view = 1,
                    can_create = 1,
                    can_edit = 1,
                    can_delete = 1,
                    can_approve = 1,
                    can_assign = 1,
                    can_evaluate = 1,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (owner_id, int(module[0]), owner_id),
            )
        conn.execute(
            """
            INSERT INTO user_profiles (user_id, font_size, color_theme, dark_mode, updated_at)
            VALUES (?, 'medium', 'emerald', 0, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO NOTHING
            """,
            (owner_id,),
        )
        _backfill_acl_projects(conn, owner_user_id=owner_id)
    _dedupe_permissions(conn)
    all_users = conn.execute("SELECT id, role FROM users WHERE is_active = 1 AND is_approved = 1").fetchall()
    for user_row in all_users:
        ensure_user_default_permissions(
            conn,
            user_id=int(user_row[0]),
            role=str(user_row[1]),
            granted_by_user_id=owner_row[0] if owner_row else None,
        )
    conn.commit()
    conn.close()
