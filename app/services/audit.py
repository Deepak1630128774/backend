import json

from ..database import get_connection


def log_audit_event(
    *,
    actor_user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: str = "",
    module_id: int | None = None,
    project_id: int | None = None,
    sub_entity_id: int | None = None,
    details: dict | None = None,
    conn=None,
) -> None:
    payload = json.dumps(details or {}, separators=(",", ":"))
    if conn is not None:
        conn.execute(
            """
            INSERT INTO audit_logs
            (actor_user_id, action, entity_type, entity_id, module_id, project_id, sub_entity_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                actor_user_id,
                action.strip().lower(),
                entity_type.strip().lower(),
                entity_id.strip(),
                module_id,
                project_id,
                sub_entity_id,
                payload,
            ),
        )
        return

    with get_connection("strategy") as strategy_conn:
        strategy_conn.execute(
            """
            INSERT INTO audit_logs
            (actor_user_id, action, entity_type, entity_id, module_id, project_id, sub_entity_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                actor_user_id,
                action.strip().lower(),
                entity_type.strip().lower(),
                entity_id.strip(),
                module_id,
                project_id,
                sub_entity_id,
                payload,
            ),
        )
