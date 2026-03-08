from typing import Any

from fastapi import Depends, HTTPException, Request

from ..database import rows_to_dicts
from .authz import get_current_user, get_data_scope_organization_id, get_effective_role
from .audit import log_audit_event

PERMISSION_ACTIONS = ("view", "create", "edit", "delete", "approve", "assign", "evaluate")
PERMISSION_COLUMNS = tuple(f"can_{action}" for action in PERMISSION_ACTIONS)

MODULE_DEFINITIONS: list[tuple[str, str]] = [
    ("fuel", "Fuel & Energy"),
    ("co2", "CO2 Projects"),
    ("macc", "MACC"),
    ("strategy", "Strategy"),
    ("admin", "Admin Dashboard"),
]

MODULE_SUB_ENTITIES: dict[str, list[str]] = {
    "fuel": ["inventory_rows", "yearly_data_rows", "reduction_targets"],
    "co2": ["input_rows", "output_rows", "costing_rows"],
    "macc": ["calculations", "evaluation_options", "evaluation_results"],
    "strategy": ["macc_selections", "portfolio_snapshots"],
}

ROLE_DEFAULTS: dict[str, dict[str, dict[str, bool]]] = {
    "owner": {
        "fuel": {col: True for col in PERMISSION_COLUMNS},
        "co2": {col: True for col in PERMISSION_COLUMNS},
        "macc": {col: True for col in PERMISSION_COLUMNS},
        "strategy": {col: True for col in PERMISSION_COLUMNS},
        "admin": {col: True for col in PERMISSION_COLUMNS},
    },
    "super_admin": {
        "fuel": {col: True for col in PERMISSION_COLUMNS},
        "co2": {col: True for col in PERMISSION_COLUMNS},
        "macc": {col: True for col in PERMISSION_COLUMNS},
        "strategy": {col: True for col in PERMISSION_COLUMNS},
        "admin": {col: True for col in PERMISSION_COLUMNS},
    },
    "buyer_admin": {
        "fuel": {col: True for col in PERMISSION_COLUMNS},
        "co2": {col: True for col in PERMISSION_COLUMNS},
        "macc": {col: True for col in PERMISSION_COLUMNS},
        "strategy": {col: True for col in PERMISSION_COLUMNS},
        "admin": {col: True for col in PERMISSION_COLUMNS},
    },
    "org_user": {
        "fuel": {
            "can_view": True,
            "can_create": True,
            "can_edit": True,
            "can_delete": True,
            "can_approve": False,
            "can_assign": False,
            "can_evaluate": True,
        },
        "co2": {
            "can_view": True,
            "can_create": True,
            "can_edit": True,
            "can_delete": True,
            "can_approve": False,
            "can_assign": False,
            "can_evaluate": True,
        },
        "macc": {
            "can_view": True,
            "can_create": True,
            "can_edit": True,
            "can_delete": True,
            "can_approve": False,
            "can_assign": False,
            "can_evaluate": True,
        },
        "strategy": {
            "can_view": True,
            "can_create": True,
            "can_edit": True,
            "can_delete": True,
            "can_approve": False,
            "can_assign": False,
            "can_evaluate": True,
        },
    },
}


def is_super_admin(user: dict) -> bool:
    role = get_effective_role(user)
    return role in {"owner", "super_admin"}


def get_scoped_organization(conn: Any, *, user: dict) -> dict | None:
    organization_id = get_data_scope_organization_id(user)
    if organization_id is None:
        return None
    row = conn.execute(
        "SELECT id, name, slug FROM organizations WHERE id = ? LIMIT 1",
        (organization_id,),
    ).fetchone()
    return dict(row) if row else None


def _project_is_in_scope(user: dict, project: dict) -> bool:
    scope_organization_id = get_data_scope_organization_id(user)
    if scope_organization_id is None:
        return False if is_super_admin(user) else project.get("organization_id") is None
    project_organization_id = project.get("organization_id")
    if project_organization_id is None:
        return False
    return int(project_organization_id) == int(scope_organization_id)


def _all_permissions(value: bool) -> dict[str, bool]:
    return {column: value for column in PERMISSION_COLUMNS}


def _permission_from_row(row: dict | None) -> dict[str, bool]:
    if not row:
        return _all_permissions(False)
    return {column: bool(row[column]) for column in PERMISSION_COLUMNS}


def _to_db_permissions(permissions: dict[str, bool] | None) -> dict[str, int]:
    data = permissions or {}
    return {column: 1 if bool(data.get(column, False)) else 0 for column in PERMISSION_COLUMNS}


def _assert_action(action: str) -> str:
    action_norm = action.strip().lower()
    if action_norm not in PERMISSION_ACTIONS:
        raise ValueError(f"Invalid permission action: {action}")
    return f"can_{action_norm}"


def _get_module(conn: Any, module_key: str) -> dict:
    row = conn.execute(
        """
        SELECT id, module_key, module_name
        FROM modules
        WHERE module_key = ?
        """,
        (module_key.strip().lower(),),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Module not found: {module_key}")
    return dict(row)


def _get_project(conn: Any, module_id: int, external_project_id: str) -> dict | None:
    row = conn.execute(
        """
        SELECT id, module_id, external_project_id, project_name, owner_user_id, created_by_user_id, organization_id
        FROM projects
        WHERE module_id = ? AND external_project_id = ?
        """,
        (module_id, external_project_id),
    ).fetchone()
    return dict(row) if row else None


def _get_sub_entity(conn: Any, project_id: int, sub_entity_key: str, external_sub_entity_id: str) -> dict | None:
    row = conn.execute(
        """
        SELECT id, project_id, sub_entity_key, external_sub_entity_id, sub_entity_name
        FROM sub_entities
        WHERE project_id = ? AND sub_entity_key = ? AND external_sub_entity_id = ?
        """,
        (project_id, sub_entity_key.strip().lower(), external_sub_entity_id),
    ).fetchone()
    return dict(row) if row else None


def _fetch_permission(
    conn: Any,
    *,
    user_id: int,
    module_id: int | None,
    project_id: int | None,
    sub_entity_id: int | None,
) -> dict | None:
    conditions = ["user_id = ?"]
    params: list[Any] = [user_id]

    if module_id is None:
        conditions.append("module_id IS NULL")
    else:
        conditions.append("module_id = ?")
        params.append(module_id)

    if project_id is None:
        conditions.append("project_id IS NULL")
    else:
        conditions.append("project_id = ?")
        params.append(project_id)

    if sub_entity_id is None:
        conditions.append("sub_entity_id IS NULL")
    else:
        conditions.append("sub_entity_id = ?")
        params.append(sub_entity_id)

    row = conn.execute(
        f"""
        SELECT id, user_id, module_id, project_id, sub_entity_id, {",".join(PERMISSION_COLUMNS)}
        FROM permissions
        WHERE {" AND ".join(conditions)}
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()
    return dict(row) if row else None


def resolve_permissions(
    conn: Any,
    *,
    user: dict,
    module_id: int,
    project: dict | None = None,
    sub_entity: dict | None = None,
) -> tuple[dict[str, bool], str]:
    if is_super_admin(user):
        return _all_permissions(True), "super_admin"

    user_id = int(user["id"])
    project_id = int(project["id"]) if project else None
    project_owner_user_id = int(project["owner_user_id"]) if project else None
    sub_entity_id = int(sub_entity["id"]) if sub_entity else None

    if project_id is not None and project_owner_user_id == user_id:
        return _all_permissions(True), "project_owner"

    if sub_entity_id is not None:
        direct_sub = _fetch_permission(
            conn,
            user_id=user_id,
            module_id=module_id,
            project_id=project_id,
            sub_entity_id=sub_entity_id,
        )
        if direct_sub is not None:
            return _permission_from_row(direct_sub), "sub_entity"

    if project_id is not None:
        direct_project = _fetch_permission(
            conn,
            user_id=user_id,
            module_id=module_id,
            project_id=project_id,
            sub_entity_id=None,
        )
        if direct_project is not None:
            return _permission_from_row(direct_project), "project"

    direct_module = _fetch_permission(
        conn,
        user_id=user_id,
        module_id=module_id,
        project_id=None,
        sub_entity_id=None,
    )
    if direct_module is not None:
        return _permission_from_row(direct_module), "module"

    return _all_permissions(False), "none"


def assert_module_permission(conn: Any, *, user: dict, module_key: str, action: str) -> dict:
    action_column = _assert_action(action)
    module = _get_module(conn, module_key)
    permissions, source = resolve_permissions(conn, user=user, module_id=int(module["id"]))
    if not permissions[action_column]:
        raise HTTPException(
            status_code=403,
            detail=f"Module permission denied: {module_key}.{action} ({source})",
        )
    return module


def assert_project_permission(
    conn: Any,
    *,
    user: dict,
    module_key: str,
    external_project_id: str,
    action: str,
    require_exists: bool = True,
) -> tuple[dict, dict | None]:
    action_column = _assert_action(action)
    module = _get_module(conn, module_key)
    project = _get_project(conn, int(module["id"]), external_project_id)

    if project is None:
        if require_exists:
            raise HTTPException(status_code=404, detail="Project registry entry not found")
        if is_super_admin(user) and get_data_scope_organization_id(user) is None:
            raise HTTPException(status_code=404, detail="Project not found")
        permissions, source = resolve_permissions(conn, user=user, module_id=int(module["id"]))
        if not permissions[action_column]:
            raise HTTPException(
                status_code=403,
                detail=f"Project permission denied: {module_key}.{external_project_id}.{action} ({source})",
            )
        return module, None

    if not _project_is_in_scope(user, project):
        raise HTTPException(status_code=404, detail="Project not found")

    permissions, source = resolve_permissions(
        conn,
        user=user,
        module_id=int(module["id"]),
        project=project,
    )
    if not permissions[action_column]:
        raise HTTPException(
            status_code=403,
            detail=f"Project permission denied: {module_key}.{external_project_id}.{action} ({source})",
        )
    return module, project


def assert_sub_entity_permission(
    conn: Any,
    *,
    user: dict,
    module_key: str,
    external_project_id: str,
    sub_entity_key: str,
    external_sub_entity_id: str,
    action: str,
    require_exists: bool = True,
) -> tuple[dict, dict | None, dict | None]:
    action_column = _assert_action(action)
    module = _get_module(conn, module_key)
    project = _get_project(conn, int(module["id"]), external_project_id)

    if project is None:
        if require_exists:
            raise HTTPException(status_code=404, detail="Project registry entry not found")
        if is_super_admin(user) and get_data_scope_organization_id(user) is None:
            raise HTTPException(status_code=404, detail="Project not found")
        permissions, source = resolve_permissions(conn, user=user, module_id=int(module["id"]))
        if not permissions[action_column]:
            raise HTTPException(
                status_code=403,
                detail=f"Sub-entity permission denied: {module_key}.{sub_entity_key}.{action} ({source})",
            )
        return module, None, None

    if not _project_is_in_scope(user, project):
        raise HTTPException(status_code=404, detail="Project not found")

    sub_entity = _get_sub_entity(conn, int(project["id"]), sub_entity_key, external_sub_entity_id)
    if sub_entity is None and require_exists:
        raise HTTPException(status_code=404, detail="Sub-entity not found")

    permissions, source = resolve_permissions(
        conn,
        user=user,
        module_id=int(module["id"]),
        project=project,
        sub_entity=sub_entity,
    )
    if not permissions[action_column]:
        raise HTTPException(
            status_code=403,
            detail=f"Sub-entity permission denied: {module_key}.{sub_entity_key}.{action} ({source})",
        )
    return module, project, sub_entity


def ensure_project_registry(
    conn: Any,
    *,
    module_key: str,
    external_project_id: str,
    project_name: str,
    creator_user_id: int,
    organization_id: int | None,
) -> dict:
    module = _get_module(conn, module_key)
    existing = _get_project(conn, int(module["id"]), external_project_id)
    if existing:
        conn.execute(
            """
            UPDATE projects
            SET project_name = ?, organization_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (project_name, organization_id, existing["id"]),
        )
        return _get_project(conn, int(module["id"]), external_project_id) or existing

    cursor = conn.execute(
        """
        INSERT INTO projects
        (module_id, external_project_id, project_name, owner_user_id, created_by_user_id, organization_id, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            int(module["id"]),
            external_project_id,
            project_name,
            creator_user_id,
            creator_user_id,
            organization_id,
        ),
    )
    project_id = int(cursor.lastrowid)
    project = _get_project(conn, int(module["id"]), external_project_id)
    if not project:
        raise HTTPException(status_code=500, detail="Failed to register project")

    ensure_default_sub_entities(
        conn,
        module_key=module_key,
        project_id=project_id,
    )

    # Project creator gets full inherited permissions at project level.
    upsert_permission(
        conn,
        user_id=creator_user_id,
        module_id=int(module["id"]),
        project_id=project_id,
        sub_entity_id=None,
        granted_by_user_id=creator_user_id,
        permissions=_all_permissions(True),
    )
    log_audit_event(
        actor_user_id=creator_user_id,
        action="project_registered",
        entity_type="project",
        entity_id=external_project_id,
        module_id=int(module["id"]),
        project_id=project_id,
        details={"project_name": project_name, "module_key": module_key},
        conn=conn,
    )
    return project


def ensure_default_sub_entities(conn: Any, *, module_key: str, project_id: int) -> None:
    keys = MODULE_SUB_ENTITIES.get(module_key, [])
    for key in keys:
        conn.execute(
            """
            INSERT OR IGNORE INTO sub_entities
            (project_id, sub_entity_key, external_sub_entity_id, sub_entity_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                project_id,
                key,
                key,
                key.replace("_", " ").title(),
            ),
        )


def list_modules(conn: Any) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, module_key, module_name
        FROM modules
        ORDER BY id ASC
        """
    ).fetchall()
    return rows_to_dicts(rows)


def list_projects(conn: Any, *, module_key: str, user: dict | None = None) -> list[dict]:
    module = _get_module(conn, module_key)
    if user is not None and is_super_admin(user) and get_data_scope_organization_id(user) is None:
        return []

    query = """
        SELECT p.id, p.external_project_id, p.project_name, p.owner_user_id, p.created_by_user_id, p.organization_id, p.updated_at
        FROM projects p
        WHERE p.module_id = ?
    """
    params: list[Any] = [module["id"]]
    if user is not None:
        scope_organization_id = get_data_scope_organization_id(user)
        if scope_organization_id is not None:
            query += " AND p.organization_id = ?"
            params.append(scope_organization_id)
    query += " ORDER BY p.updated_at DESC, p.id DESC"
    rows = conn.execute(query, tuple(params)).fetchall()
    return rows_to_dicts(rows)


def list_sub_entities(conn: Any, *, module_key: str, external_project_id: str) -> list[dict]:
    module = _get_module(conn, module_key)
    project = _get_project(conn, int(module["id"]), external_project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    rows = conn.execute(
        """
        SELECT id, sub_entity_key, external_sub_entity_id, sub_entity_name, updated_at
        FROM sub_entities
        WHERE project_id = ?
        ORDER BY sub_entity_key ASC
        """,
        (project["id"],),
    ).fetchall()
    return rows_to_dicts(rows)


def upsert_permission(
    conn: Any,
    *,
    user_id: int,
    module_id: int | None,
    project_id: int | None,
    sub_entity_id: int | None,
    granted_by_user_id: int | None,
    permissions: dict[str, bool] | None,
) -> None:
    perm = _to_db_permissions(permissions)
    conditions = ["user_id = ?"]
    params: list[Any] = [user_id]

    if module_id is None:
        conditions.append("module_id IS NULL")
    else:
        conditions.append("module_id = ?")
        params.append(module_id)

    if project_id is None:
        conditions.append("project_id IS NULL")
    else:
        conditions.append("project_id = ?")
        params.append(project_id)

    if sub_entity_id is None:
        conditions.append("sub_entity_id IS NULL")
    else:
        conditions.append("sub_entity_id = ?")
        params.append(sub_entity_id)

    existing = conn.execute(
        f"""
        SELECT id
        FROM permissions
        WHERE {' AND '.join(conditions)}
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()

    if existing:
        conn.execute(
            f"""
            UPDATE permissions
            SET {",".join(f"{col} = ?" for col in PERMISSION_COLUMNS)},
                granted_by_user_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                *(perm[col] for col in PERMISSION_COLUMNS),
                granted_by_user_id,
                int(existing["id"] if isinstance(existing, dict) else existing[0]),
            ),
        )
        # Keep only one record for this scope to avoid duplicated UI rows.
        conn.execute(
            f"""
            DELETE FROM permissions
            WHERE {' AND '.join(conditions)}
              AND id != ?
            """,
            (*params, int(existing["id"] if isinstance(existing, dict) else existing[0])),
        )
        return

    conn.execute(
        f"""
        INSERT INTO permissions
        (user_id, module_id, project_id, sub_entity_id, {",".join(PERMISSION_COLUMNS)}, granted_by_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, {",".join("?" for _ in PERMISSION_COLUMNS)}, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            user_id,
            module_id,
            project_id,
            sub_entity_id,
            *(perm[col] for col in PERMISSION_COLUMNS),
            granted_by_user_id,
        ),
    )


def remove_permission(
    conn: Any,
    *,
    user_id: int,
    module_id: int | None,
    project_id: int | None,
    sub_entity_id: int | None,
) -> None:
    conditions = ["user_id = ?"]
    params: list[Any] = [user_id]

    if module_id is None:
        conditions.append("module_id IS NULL")
    else:
        conditions.append("module_id = ?")
        params.append(module_id)

    if project_id is None:
        conditions.append("project_id IS NULL")
    else:
        conditions.append("project_id = ?")
        params.append(project_id)

    if sub_entity_id is None:
        conditions.append("sub_entity_id IS NULL")
    else:
        conditions.append("sub_entity_id = ?")
        params.append(sub_entity_id)

    conn.execute(
        f"DELETE FROM permissions WHERE {' AND '.join(conditions)}",
        tuple(params),
    )


def ensure_user_default_permissions(
    conn: Any,
    *,
    user_id: int,
    role: str,
    granted_by_user_id: int | None = None,
) -> None:
    normalized_role = role.strip().lower()
    if normalized_role == "org_admin":
        normalized_role = "buyer_admin"
    defaults = ROLE_DEFAULTS.get(normalized_role)
    if not defaults:
        return
    module_rows = conn.execute("SELECT id, module_key FROM modules").fetchall()
    module_map: dict[str, int] = {}
    for row in module_rows:
        if isinstance(row, dict):
            module_map[str(row["module_key"]).strip().lower()] = int(row["id"])
        else:
            module_map[str(row[1]).strip().lower()] = int(row[0])

    for module_key, permissions in defaults.items():
        module_id = module_map.get(module_key)
        if not module_id:
            continue
        upsert_permission(
            conn,
            user_id=user_id,
            module_id=module_id,
            project_id=None,
            sub_entity_id=None,
            granted_by_user_id=granted_by_user_id,
            permissions=permissions,
        )

    conn.execute(
        """
        INSERT INTO user_profiles (user_id, font_size, color_theme, dark_mode, updated_at)
        VALUES (?, 'medium', 'emerald', 0, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO NOTHING
        """,
        (user_id,),
    )


def transfer_project_ownership(
    conn: Any,
    *,
    module_key: str,
    external_project_id: str,
    new_owner_user_id: int,
    actor_user_id: int,
) -> dict:
    module = _get_module(conn, module_key)
    project = _get_project(conn, int(module["id"]), external_project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    conn.execute(
        """
        UPDATE projects
        SET owner_user_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (new_owner_user_id, project["id"]),
    )
    upsert_permission(
        conn,
        user_id=new_owner_user_id,
        module_id=int(module["id"]),
        project_id=int(project["id"]),
        sub_entity_id=None,
        granted_by_user_id=actor_user_id,
        permissions=_all_permissions(True),
    )
    log_audit_event(
        actor_user_id=actor_user_id,
        action="ownership_transferred",
        entity_type="project",
        entity_id=external_project_id,
        module_id=int(module["id"]),
        project_id=int(project["id"]),
        details={
            "new_owner_user_id": new_owner_user_id,
            "previous_owner_user_id": project["owner_user_id"],
        },
        conn=conn,
    )
    updated = _get_project(conn, int(module["id"]), external_project_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Project ownership transfer failed")
    return updated


def get_permission_snapshot(conn: Any, *, user: dict) -> dict:
    user_id = int(user["id"])
    scope_organization_id = get_data_scope_organization_id(user)
    project_scope_clause = ""
    project_scope_params: list[Any] = []
    if is_super_admin(user) and scope_organization_id is None:
        project_scope_clause = " AND 1 = 0"
    elif scope_organization_id is not None:
        project_scope_clause = " AND p.organization_id = ?"
        project_scope_params.append(scope_organization_id)

    module_rows = conn.execute(
        f"""
        SELECT
            m.module_key,
            m.module_name,
            {",".join(f"COALESCE(p.{col}, 0) AS {col}" for col in PERMISSION_COLUMNS)}
        FROM modules m
        LEFT JOIN permissions p ON p.id = (
            SELECT p2.id
            FROM permissions p2
            WHERE p2.user_id = ?
              AND p2.module_id = m.id
              AND p2.project_id IS NULL
              AND p2.sub_entity_id IS NULL
            ORDER BY p2.updated_at DESC, p2.id DESC
            LIMIT 1
        )
        ORDER BY m.id ASC
        """,
        (user_id,),
    ).fetchall()

    project_rows = conn.execute(
        f"""
        SELECT
            m.module_key,
            p.external_project_id,
            p.project_name,
            p.owner_user_id,
            {",".join(f"COALESCE(pr.{col}, 0) AS {col}" for col in PERMISSION_COLUMNS)}
        FROM projects p
        JOIN modules m ON m.id = p.module_id
        LEFT JOIN permissions pr ON pr.id = (
            SELECT p2.id
            FROM permissions p2
            WHERE p2.user_id = ?
              AND p2.project_id = p.id
              AND p2.sub_entity_id IS NULL
            ORDER BY p2.updated_at DESC, p2.id DESC
            LIMIT 1
        )
        WHERE 1 = 1 {project_scope_clause}
        ORDER BY m.module_key, p.updated_at DESC
        """,
        (user_id, *project_scope_params),
    ).fetchall()

    sub_rows = conn.execute(
        f"""
        SELECT
            m.module_key,
            p.external_project_id,
            s.sub_entity_key,
            s.external_sub_entity_id,
            {",".join(f"COALESCE(pr.{col}, 0) AS {col}" for col in PERMISSION_COLUMNS)}
        FROM sub_entities s
        JOIN projects p ON p.id = s.project_id
        JOIN modules m ON m.id = p.module_id
        LEFT JOIN permissions pr ON pr.id = (
            SELECT p2.id
            FROM permissions p2
            WHERE p2.user_id = ?
              AND p2.sub_entity_id = s.id
            ORDER BY p2.updated_at DESC, p2.id DESC
            LIMIT 1
        )
        WHERE 1 = 1 {project_scope_clause}
        ORDER BY m.module_key, p.external_project_id, s.sub_entity_key
        """,
        (user_id, *project_scope_params),
    ).fetchall()

    owned_rows = conn.execute(
        f"""
        SELECT m.module_key, p.external_project_id
        FROM projects p
        JOIN modules m ON m.id = p.module_id
        WHERE p.owner_user_id = ?{project_scope_clause}
        """,
        (user_id, *project_scope_params),
    ).fetchall()

    module_permissions = []
    for row in module_rows:
        module_permissions.append(
            {
                "module_key": row["module_key"],
                "module_name": row["module_name"],
                **_permission_from_row(dict(row)),
            }
        )

    project_permissions = []
    for row in project_rows:
        project_permissions.append(
            {
                "module_key": row["module_key"],
                "project_id": row["external_project_id"],
                "project_name": row["project_name"],
                "owner_user_id": row["owner_user_id"],
                **_permission_from_row(dict(row)),
            }
        )

    sub_permissions = []
    for row in sub_rows:
        sub_permissions.append(
            {
                "module_key": row["module_key"],
                "project_id": row["external_project_id"],
                "sub_entity_key": row["sub_entity_key"],
                "sub_entity_id": row["external_sub_entity_id"],
                **_permission_from_row(dict(row)),
            }
        )

    owned_projects = [
        {"module_key": row["module_key"], "project_id": row["external_project_id"]}
        for row in owned_rows
    ]

    return {
        "module_permissions": module_permissions,
        "project_permissions": project_permissions,
        "sub_entity_permissions": sub_permissions,
        "owned_projects": owned_projects,
    }


def preview_access(
    conn: Any,
    *,
    target_user: dict,
    module_key: str,
    action: str,
    external_project_id: str = "",
    sub_entity_key: str = "",
    external_sub_entity_id: str = "",
) -> dict:
    action_column = _assert_action(action)
    module = _get_module(conn, module_key)
    project = None
    sub_entity = None

    if external_project_id:
        project = _get_project(conn, int(module["id"]), external_project_id)
    if project and sub_entity_key and external_sub_entity_id:
        sub_entity = _get_sub_entity(conn, int(project["id"]), sub_entity_key, external_sub_entity_id)

    permissions, source = resolve_permissions(
        conn,
        user=target_user,
        module_id=int(module["id"]),
        project=project,
        sub_entity=sub_entity,
    )
    return {
        "granted": bool(permissions[action_column]),
        "source": source,
        "action": action,
        "permissions": permissions,
    }


def has_project_access(
    conn: Any,
    *,
    user: dict,
    module_key: str,
    external_project_id: str,
    action: str = "view",
) -> bool:
    try:
        assert_project_permission(
            conn,
            user=user,
            module_key=module_key,
            external_project_id=external_project_id,
            action=action,
            require_exists=False,
        )
        return True
    except HTTPException:
        return False


def check_module_permission(module_key: str, action: str):
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        from ..database import get_connection

        with get_connection("strategy") as conn:
            assert_module_permission(conn, user=user, module_key=module_key, action=action)
        return user

    return dependency


def check_project_permission(
    module_key: str,
    action: str,
    project_param: str,
    require_exists: bool = True,
):
    def dependency(user: dict = Depends(get_current_user), request: Request = None) -> dict:
        project_id = ""
        if request is not None:
            project_id = str(request.path_params.get(project_param) or request.query_params.get(project_param) or "")
        if not project_id:
            raise HTTPException(status_code=400, detail=f"Missing project identifier: {project_param}")
        from ..database import get_connection

        with get_connection("strategy") as conn:
            assert_project_permission(
                conn,
                user=user,
                module_key=module_key,
                external_project_id=project_id,
                action=action,
                require_exists=require_exists,
            )
        return user

    return dependency


def check_sub_entity_permission(
    module_key: str,
    action: str,
    project_param: str,
    sub_entity_key: str,
    sub_entity_param: str,
    require_exists: bool = True,
):
    def dependency(user: dict = Depends(get_current_user), request: Request = None) -> dict:
        project_id = ""
        sub_entity_id = ""
        if request is not None:
            project_id = str(request.path_params.get(project_param) or request.query_params.get(project_param) or "")
            sub_entity_id = str(request.path_params.get(sub_entity_param) or request.query_params.get(sub_entity_param) or "")
        if not project_id:
            raise HTTPException(status_code=400, detail=f"Missing project identifier: {project_param}")
        if not sub_entity_id:
            raise HTTPException(status_code=400, detail=f"Missing sub-entity identifier: {sub_entity_param}")
        from ..database import get_connection

        with get_connection("strategy") as conn:
            assert_sub_entity_permission(
                conn,
                user=user,
                module_key=module_key,
                external_project_id=project_id,
                sub_entity_key=sub_entity_key,
                external_sub_entity_id=sub_entity_id,
                action=action,
                require_exists=require_exists,
            )
        return user

    return dependency
