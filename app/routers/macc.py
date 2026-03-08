import json

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection, row_to_dict, rows_to_dicts
from ..schemas.macc import MaccEvaluateRequest, MaccProjectUpsertRequest, NpvRequest
from ..services.acl import (
    assert_module_permission,
    assert_project_permission,
    assert_sub_entity_permission,
    check_module_permission,
    check_project_permission,
    ensure_project_registry,
    has_project_access,
    list_projects as list_acl_projects,
)
from ..services.authz import get_current_user, get_data_scope_organization_id, get_effective_role
from ..services.tenant import assert_payload_organization_access, require_org_member_or_owner

router = APIRouter(prefix="/api/macc", tags=["macc"], dependencies=[Depends(require_org_member_or_owner)])


def _normalize_organization_name(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _scoped_organization_name(user: dict) -> str | None:
    name = str(user.get("selected_organization_name") or user.get("effective_organization_name") or "").strip()
    return name or None


def _resolve_project_scope(project_id: str, organization_name: str | None) -> tuple[int | None, str | None]:
    normalized_name = _normalize_organization_name(organization_name)

    with get_connection("strategy") as conn:
        module = conn.execute("SELECT id FROM modules WHERE module_key = 'macc' LIMIT 1").fetchone()
        if module:
            registry_row = conn.execute(
                """
                SELECT p.organization_id, o.name
                FROM projects p
                LEFT JOIN organizations o ON o.id = p.organization_id
                WHERE p.module_id = ? AND p.external_project_id = ?
                LIMIT 1
                """,
                (module["id"], project_id),
            ).fetchone()
            if registry_row and registry_row["organization_id"] is not None:
                return int(registry_row["organization_id"]), str(registry_row["name"] or "").strip() or None

        if not normalized_name:
            return None, None

        org_rows = conn.execute("SELECT id, name FROM organizations").fetchall()

    for row in org_rows:
        if _normalize_organization_name(row["name"]) == normalized_name:
            return int(row["id"]), str(row["name"] or "").strip() or None
    return None, str(organization_name or "").strip() or None


def _assert_project_scope(user: dict, project_id: str, organization_name: str | None) -> tuple[int | None, str | None]:
    scoped_organization_id = get_data_scope_organization_id(user)
    if get_effective_role(user) in {"owner", "super_admin"} and scoped_organization_id is None:
        raise HTTPException(status_code=404, detail="MACC project not found")
    if scoped_organization_id is None:
        return None, str(organization_name or "").strip() or None

    project_organization_id, resolved_organization_name = _resolve_project_scope(project_id, organization_name)
    if project_organization_id is not None:
        if int(project_organization_id) != int(scoped_organization_id):
            raise HTTPException(status_code=404, detail="MACC project not found")
        return project_organization_id, resolved_organization_name

    scoped_name = _normalize_organization_name(_scoped_organization_name(user))
    normalized_value = _normalize_organization_name(organization_name)
    if scoped_name and normalized_value and scoped_name == normalized_value:
        return scoped_organization_id, str(organization_name or "").strip() or None

    if normalized_value:
        raise HTTPException(status_code=404, detail="MACC project not found")

    return scoped_organization_id, _scoped_organization_name(user)


def calculate_npv(rate: float, cashflows: list[float]) -> float:
    rate = float(rate)
    return sum(cf / (1 + rate) ** t for t, cf in enumerate(cashflows))


@router.get("/projects")
def list_projects(user: dict = Depends(check_module_permission("macc", "view"))) -> list[dict]:
    with get_connection("strategy") as acl_conn:
        registry_rows = list_acl_projects(acl_conn, module_key="macc", user=user)
    project_ids = [str(row["external_project_id"]) for row in registry_rows]
    if not project_ids:
        return []

    with get_connection("npv") as conn:
        placeholders = ",".join("?" for _ in project_ids)
        rows = conn.execute(
            f"""
            SELECT id, organization, project_name, initiative, industry, country,
                   target_year, mac, total_co2_diff, created_at
            FROM npv_projects
            WHERE id IN ({placeholders})
            ORDER BY created_at DESC
            """,
            tuple(project_ids),
        ).fetchall()
    items = {str(item["id"]): item for item in rows_to_dicts(rows)}
    return [items[project_id] for project_id in project_ids if project_id in items]


@router.get("/projects/{project_id}")
def get_project(
    project_id: str,
    user: dict = Depends(check_project_permission("macc", "view", "project_id", require_exists=False)),
) -> dict:
    with get_connection("npv") as conn:
        row = conn.execute(
            "SELECT * FROM npv_projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="MACC project not found")
    _, resolved_organization_name = _assert_project_scope(user, project_id, row["organization"])
    data = row_to_dict(row)
    if not str(data.get("organization") or "").strip() and resolved_organization_name:
        data["organization"] = resolved_organization_name
    for field in ("material_energy_data", "option1_data", "option2_data", "result"):
        data[field] = json.loads(data[field]) if data.get(field) else {}
    return data


@router.post("/projects")
def upsert_project(
    payload: MaccProjectUpsertRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    resolved_organization_name = _scoped_organization_name(user) or str(payload.organization or "").strip()

    with get_connection("npv") as conn:
        existing = conn.execute(
            "SELECT id FROM npv_projects WHERE id = ?",
            (payload.id,),
        ).fetchone()

    with get_connection("strategy") as acl_conn:
        assert_payload_organization_access(acl_conn, user=user, organization_name=resolved_organization_name)
        if existing:
            assert_project_permission(
                acl_conn,
                user=user,
                module_key="macc",
                external_project_id=payload.id,
                action="edit",
                require_exists=False,
            )
        else:
            assert_module_permission(acl_conn, user=user, module_key="macc", action="create")

        ensure_project_registry(
            acl_conn,
            module_key="macc",
            external_project_id=payload.id,
            project_name=payload.project_name or payload.id,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )
        for sub_key in ("calculations", "evaluation_options", "evaluation_results"):
            assert_sub_entity_permission(
                acl_conn,
                user=user,
                module_key="macc",
                external_project_id=payload.id,
                sub_entity_key=sub_key,
                external_sub_entity_id=sub_key,
                action="edit",
                require_exists=False,
            )

    with get_connection("npv") as conn:
        existing = conn.execute(
            "SELECT id FROM npv_projects WHERE id = ?",
            (payload.id,),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE npv_projects SET
                    organization = ?, entity_name = ?, unit_name = ?, project_name = ?,
                    base_year = ?, target_year = ?, implementation_date = ?, life_span = ?,
                    project_owner = ?, initiative = ?, industry = ?, country = ?, year = ?,
                    material_energy_data = ?, option1_data = ?, option2_data = ?, result = ?,
                    npv1 = ?, npv2 = ?, mac = ?, total_co2_diff = ?
                WHERE id = ?
                """,
                (
                    resolved_organization_name,
                    payload.entity_name,
                    payload.unit_name,
                    payload.project_name,
                    payload.base_year,
                    payload.target_year,
                    payload.implementation_date,
                    payload.life_span,
                    payload.project_owner,
                    payload.initiative,
                    payload.industry,
                    payload.country,
                    payload.year,
                    json.dumps(payload.material_energy_data),
                    json.dumps(payload.option1_data),
                    json.dumps(payload.option2_data),
                    json.dumps(payload.result),
                    payload.npv1,
                    payload.npv2,
                    payload.mac,
                    payload.total_co2_diff,
                    payload.id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO npv_projects
                (id, organization, entity_name, unit_name, project_name, base_year, target_year,
                 implementation_date, life_span, project_owner, initiative, industry, country, year,
                 material_energy_data, option1_data, option2_data, result, npv1, npv2, mac, total_co2_diff)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    resolved_organization_name,
                    payload.entity_name,
                    payload.unit_name,
                    payload.project_name,
                    payload.base_year,
                    payload.target_year,
                    payload.implementation_date,
                    payload.life_span,
                    payload.project_owner,
                    payload.initiative,
                    payload.industry,
                    payload.country,
                    payload.year,
                    json.dumps(payload.material_energy_data),
                    json.dumps(payload.option1_data),
                    json.dumps(payload.option2_data),
                    json.dumps(payload.result),
                    payload.npv1,
                    payload.npv2,
                    payload.mac,
                    payload.total_co2_diff,
                ),
            )

    return {"status": "ok", "id": payload.id}


@router.delete("/projects/{project_id}")
def delete_project(
    project_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_project_permission(
            acl_conn,
            user=user,
            module_key="macc",
            external_project_id=project_id,
            action="delete",
            require_exists=False,
        )

    with get_connection("npv") as conn:
        row = conn.execute(
            "SELECT id, organization FROM npv_projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="MACC project not found")
        _assert_project_scope(user, project_id, row["organization"])
        conn.execute("DELETE FROM npv_projects WHERE id = ?", (project_id,))
    with get_connection("strategy") as acl_conn:
        module = acl_conn.execute("SELECT id FROM modules WHERE module_key = 'macc'").fetchone()
        if module:
            acl_conn.execute(
                "DELETE FROM projects WHERE module_id = ? AND external_project_id = ?",
                (module["id"], project_id),
            )
    return {"status": "deleted", "id": project_id}


@router.post("/calculate-npv")
def npv(payload: NpvRequest, _: dict = Depends(check_module_permission("macc", "evaluate"))) -> dict:
    return {"npv": calculate_npv(payload.rate / 100 if payload.rate > 1 else payload.rate, payload.cashflows)}


@router.post("/evaluate")
def evaluate(
    payload: MaccEvaluateRequest,
    _: dict = Depends(check_module_permission("macc", "evaluate")),
) -> dict:
    rate_1 = payload.option1_discount_rate / 100 if payload.option1_discount_rate > 1 else payload.option1_discount_rate
    rate_2 = payload.option2_discount_rate / 100 if payload.option2_discount_rate > 1 else payload.option2_discount_rate
    npv_1 = calculate_npv(rate_1, payload.option1_cashflows)
    npv_2 = calculate_npv(rate_2, payload.option2_cashflows)

    mac = None
    if payload.total_co2_diff:
        mac = (npv_2 - npv_1) / payload.total_co2_diff

    return {
        "npv1": npv_1,
        "npv2": npv_2,
        "total_co2_diff": payload.total_co2_diff,
        "mac": mac,
    }
