import json

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection, row_to_dict, rows_to_dicts
from ..schemas.co2 import Co2CalculationRequest, Co2ProjectUpsertRequest, TrackingSaveRequest
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

router = APIRouter(prefix="/api/co2", tags=["co2"], dependencies=[Depends(require_org_member_or_owner)])


def _normalize_name(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _scoped_organization_name(user: dict) -> str | None:
    name = str(user.get("selected_organization_name") or user.get("effective_organization_name") or "").strip()
    return name or None


def _assert_project_row_scope(user: dict, organization_name: str | None) -> None:
    scoped_name = _scoped_organization_name(user)
    if get_effective_role(user) in {"owner", "super_admin"} and not scoped_name:
        raise HTTPException(status_code=404, detail="Project not found")
    if not scoped_name:
        return
    normalized_scope = " ".join(scoped_name.lower().split())
    normalized_value = " ".join(str(organization_name or "").strip().lower().split())
    if normalized_scope != normalized_value:
        raise HTTPException(status_code=404, detail="Project not found")


def _co2_name_exists_in_scope(*, project_code: str, project_name: str, organization_name: str, scope_organization_id: int | None) -> bool:
    normalized_project_name = _normalize_name(project_name)
    if not normalized_project_name:
        return False

    scoped_project_codes: set[str] = set()
    if scope_organization_id is not None:
        with get_connection("strategy") as acl_conn:
            module = acl_conn.execute(
                "SELECT id FROM modules WHERE module_key = 'co2' LIMIT 1"
            ).fetchone()
            if module:
                rows = acl_conn.execute(
                    """
                    SELECT external_project_id
                    FROM projects
                    WHERE module_id = ? AND organization_id = ? AND external_project_id != ?
                    """,
                    (module["id"], scope_organization_id, project_code),
                ).fetchall()
                scoped_project_codes = {str(row["external_project_id"]) for row in rows}

    with get_connection("co2") as conn:
        if scoped_project_codes:
            placeholders = ",".join("?" for _ in scoped_project_codes)
            row = conn.execute(
                f"""
                SELECT project_code FROM projects
                WHERE project_code IN ({placeholders})
                    AND lower(trim(project_name)) = lower(trim(?))
                LIMIT 1
                """,
                (*scoped_project_codes, project_name),
            ).fetchone()
            if row:
                return True

        row = conn.execute(
            """
            SELECT project_code FROM projects
            WHERE lower(trim(project_name)) = lower(trim(?))
                AND lower(trim(COALESCE(organization, ''))) = lower(trim(?))
                AND project_code != ?
            LIMIT 1
            """,
            (project_name, organization_name, project_code),
        ).fetchone()
        return bool(row)


def _safe_float(value: float | int | str | None) -> float:
    try:
        if value is None:
            return 0.0
        return float(str(value).strip() or 0.0)
    except Exception:
        return 0.0


def _co2_from_row(row: dict, method: str, primary_output: float, phase: str) -> float:
    ef = _safe_float(row.get("ef", 0.0))
    if method == "specific":
        specific = _safe_float(row.get(f"spec_{phase}", 0.0))
        return specific * primary_output * ef
    absolute = _safe_float(row.get(f"abs_{phase}", 0.0))
    return absolute * ef


def _calculate(payload: Co2CalculationRequest) -> tuple[dict, dict]:
    input_before = sum(
        _co2_from_row(row.model_dump(), payload.method, payload.primary_output_before, "before")
        for row in payload.input_data
    )
    input_after = sum(
        _co2_from_row(row.model_dump(), payload.method, payload.primary_output_after, "after")
        for row in payload.input_data
    )

    output_before = sum(
        _co2_from_row(row.model_dump(), payload.method, payload.primary_output_before, "before")
        for row in payload.output_data
    )
    output_after = sum(
        _co2_from_row(row.model_dump(), payload.method, payload.primary_output_after, "after")
        for row in payload.output_data
    )

    net_before = input_before - output_before
    net_after = input_after - output_after
    reduction = net_before - net_after

    sp_net_before = net_before / payload.amp_before if payload.amp_before else 0.0
    sp_net_after = net_after / payload.amp_after if payload.amp_after else 0.0
    sp_net_reduction = sp_net_before - sp_net_after

    emission_results = {
        "Input CO2_Before": input_before,
        "Input CO2_After": input_after,
        "Input CO2_Net": input_before - input_after,
        "Output CO2_Before": output_before,
        "Output CO2_After": output_after,
        "Output CO2_Net": output_before - output_after,
        "Net CO2_Before": net_before,
        "Net CO2_After": net_after,
        "Net CO2_Net": net_before - net_after,
        "Sp.Net_Before": sp_net_before,
        "Sp.Net_After": sp_net_after,
        "Sp.Net_Net": sp_net_reduction,
        "CO2 reduction_Net": reduction,
    }

    costing_results: dict[str, float] = {}
    for row in payload.costing_data:
        key = row.parameter
        before = _safe_float(row.before)
        after = _safe_float(row.after)
        costing_results[f"{key}_Before"] = before
        costing_results[f"{key}_After"] = after
        costing_results[f"{key}_Net"] = before - after

    return emission_results, costing_results


@router.get("/projects")
def list_projects(user: dict = Depends(check_module_permission("co2", "view"))) -> list[dict]:
    with get_connection("strategy") as acl_conn:
        registry_rows = list_acl_projects(acl_conn, module_key="co2", user=user)
    project_codes = [str(row["external_project_id"]) for row in registry_rows]
    if not project_codes:
        return []

    with get_connection("co2") as conn:
        placeholders = ",".join("?" for _ in project_codes)
        rows = conn.execute(
            f"""
            SELECT project_code, organization, entity_name, unit_name, project_name, base_year,
                   target_year, project_owner, calculation_method, created_at
            FROM projects
            WHERE project_code IN ({placeholders})
            ORDER BY created_at DESC
            """,
            tuple(project_codes),
        ).fetchall()
    items = {str(item["project_code"]): item for item in rows_to_dicts(rows)}
    return [items[project_code] for project_code in project_codes if project_code in items]


@router.get("/projects/{project_code}")
def get_project(
    project_code: str,
    user: dict = Depends(check_project_permission("co2", "view", "project_code", require_exists=False)),
) -> dict:
    with get_connection("co2") as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE project_code = ?", (project_code,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
    _assert_project_row_scope(user, row["organization"])
    data = row_to_dict(row)
    for field in ("input_data", "output_data", "costing_data", "emission_results", "costing_results"):
        value = data.get(field)
        data[field] = json.loads(value) if value else []
    return data


@router.post("/projects")
def upsert_project(
    payload: Co2ProjectUpsertRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    resolved_organization_name = _scoped_organization_name(user) or str(payload.organization or "").strip()

    with get_connection("co2") as conn:
        existing = conn.execute(
            "SELECT project_code FROM projects WHERE project_code = ?",
            (payload.project_code,),
        ).fetchone()

    with get_connection("strategy") as acl_conn:
        assert_payload_organization_access(acl_conn, user=user, organization_name=resolved_organization_name)
        if existing:
            assert_project_permission(
                acl_conn,
                user=user,
                module_key="co2",
                external_project_id=payload.project_code,
                action="edit",
                require_exists=False,
            )
        else:
            assert_module_permission(acl_conn, user=user, module_key="co2", action="create")

        ensure_project_registry(
            acl_conn,
            module_key="co2",
            external_project_id=payload.project_code,
            project_name=payload.project_name or payload.project_code,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )
        # CO2 project saves mutate row-level sub-entities.
        for sub_key in ("input_rows", "output_rows", "costing_rows"):
            assert_sub_entity_permission(
                acl_conn,
                user=user,
                module_key="co2",
                external_project_id=payload.project_code,
                sub_entity_key=sub_key,
                external_sub_entity_id=sub_key,
                action="edit",
                require_exists=False,
            )

    if _co2_name_exists_in_scope(
        project_code=payload.project_code,
        project_name=payload.project_name,
        organization_name=resolved_organization_name,
        scope_organization_id=get_data_scope_organization_id(user),
    ):
        raise HTTPException(status_code=409, detail="Project name already exists")

    with get_connection("co2") as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO projects
            (project_code, organization, entity_name, unit_name, project_name, base_year, target_year,
             implementation_date, capex, life_span, project_owner, input_data, output_data, costing_data,
             amp_before, amp_after, amp_uom, emission_results, costing_results, calculation_method, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                payload.project_code,
                resolved_organization_name,
                payload.entity_name,
                payload.unit_name,
                payload.project_name,
                payload.base_year,
                payload.target_year,
                payload.implementation_date,
                payload.capex,
                payload.life_span,
                payload.project_owner,
                json.dumps(payload.input_data),
                json.dumps(payload.output_data),
                json.dumps(payload.costing_data),
                payload.amp_before,
                payload.amp_after,
                payload.amp_uom,
                json.dumps(payload.emission_results or {}),
                json.dumps(payload.costing_results or {}),
                payload.calculation_method,
            ),
        )
    return {"status": "ok", "project_code": payload.project_code}


@router.delete("/projects/{project_code}")
def delete_project(
    project_code: str,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_project_permission(
            acl_conn,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            action="delete",
            require_exists=False,
        )

    with get_connection("co2") as conn:
        row = conn.execute(
            "SELECT project_code, organization FROM projects WHERE project_code = ?",
            (project_code,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        _assert_project_row_scope(user, row["organization"])
        conn.execute("DELETE FROM project_actuals WHERE project_code = ?", (project_code,))
        conn.execute("DELETE FROM amp_actuals_tracking WHERE project_code = ?", (project_code,))
        conn.execute("DELETE FROM projects WHERE project_code = ?", (project_code,))
    with get_connection("strategy") as acl_conn:
        module = acl_conn.execute("SELECT id FROM modules WHERE module_key = 'co2'").fetchone()
        if module:
            acl_conn.execute(
                "DELETE FROM projects WHERE module_id = ? AND external_project_id = ?",
                (module["id"], project_code),
            )
    return {"status": "deleted", "project_code": project_code}


@router.post("/calculate")
def calculate(
    payload: Co2CalculationRequest,
    _: dict = Depends(check_module_permission("co2", "evaluate")),
) -> dict:
    emission_results, costing_results = _calculate(payload)
    return {"emission_results": emission_results, "costing_results": costing_results}


@router.get("/projects/{project_code}/tracking/years")
def list_tracking_years(
    project_code: str,
    user: dict = Depends(check_project_permission("co2", "view", "project_code", require_exists=False)),
) -> list[int]:
    with get_connection("co2") as conn:
        project = conn.execute(
            "SELECT project_code, organization FROM projects WHERE project_code = ?",
            (project_code,),
        ).fetchone()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        _assert_project_row_scope(user, project["organization"])

        input_years = conn.execute(
            "SELECT DISTINCT year_number FROM project_actuals WHERE project_code = ?",
            (project_code,),
        ).fetchall()
        amp_years = conn.execute(
            "SELECT DISTINCT year_number FROM amp_actuals_tracking WHERE project_code = ?",
            (project_code,),
        ).fetchall()

    years = {int(row["year_number"]) for row in input_years + amp_years if row["year_number"] is not None}
    return sorted(years)


@router.get("/projects/{project_code}/tracking/{year}")
def get_tracking(
    project_code: str,
    year: int,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            sub_entity_key="input_rows",
            external_sub_entity_id="input_rows",
            action="view",
            require_exists=False,
        )
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            sub_entity_key="output_rows",
            external_sub_entity_id="output_rows",
            action="view",
            require_exists=False,
        )
    with get_connection("co2") as conn:
        project = conn.execute(
            "SELECT project_code, organization FROM projects WHERE project_code = ?",
            (project_code,),
        ).fetchone()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        _assert_project_row_scope(user, project["organization"])

        rows = conn.execute(
            """
            SELECT section_type, material_name, row_index, absolute_value, specific_value
            FROM project_actuals
            WHERE project_code = ? AND year_number = ?
            ORDER BY section_type, row_index
            """,
            (project_code, year),
        ).fetchall()

        amp_row = conn.execute(
            """
            SELECT amp_value
            FROM amp_actuals_tracking
            WHERE project_code = ? AND year_number = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (project_code, year),
        ).fetchone()

    input_rows = []
    output_rows = []
    for row in rows:
        item = {
            "material_name": row["material_name"],
            "row_index": row["row_index"],
            "absolute_value": row["absolute_value"],
            "specific_value": row["specific_value"],
        }
        if row["section_type"] == "input":
            input_rows.append(item)
        elif row["section_type"] == "output":
            output_rows.append(item)

    return {
        "year": year,
        "input_rows": input_rows,
        "output_rows": output_rows,
        "amp_value": amp_row["amp_value"] if amp_row else None,
    }


@router.put("/projects/{project_code}/tracking/{year}")
def save_tracking(
    project_code: str,
    year: int,
    payload: TrackingSaveRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        ensure_project_registry(
            acl_conn,
            module_key="co2",
            external_project_id=project_code,
            project_name=project_code,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            sub_entity_key="input_rows",
            external_sub_entity_id="input_rows",
            action="edit",
            require_exists=False,
        )
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            sub_entity_key="output_rows",
            external_sub_entity_id="output_rows",
            action="edit",
            require_exists=False,
        )

    with get_connection("co2") as conn:
        project = conn.execute(
            "SELECT project_code, organization FROM projects WHERE project_code = ?",
            (project_code,),
        ).fetchone()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        _assert_project_row_scope(user, project["organization"])

        for row in payload.input_rows:
            conn.execute(
                """
                INSERT OR REPLACE INTO project_actuals
                (project_code, section_type, material_name, row_index, year_number, absolute_value, specific_value)
                VALUES (?, 'input', ?, ?, ?, ?, ?)
                """,
                (
                    project_code,
                    row.material_name,
                    row.row_index,
                    year,
                    row.absolute_value,
                    row.specific_value,
                ),
            )

        for row in payload.output_rows:
            conn.execute(
                """
                INSERT OR REPLACE INTO project_actuals
                (project_code, section_type, material_name, row_index, year_number, absolute_value, specific_value)
                VALUES (?, 'output', ?, ?, ?, ?, ?)
                """,
                (
                    project_code,
                    row.material_name,
                    row.row_index,
                    year,
                    row.absolute_value,
                    row.specific_value,
                ),
            )

        conn.execute(
            """
            INSERT OR REPLACE INTO amp_actuals_tracking (project_code, year_number, amp_value)
            VALUES (?, ?, ?)
            """,
            (project_code, year, payload.amp_value),
        )

    return {"status": "ok", "project_code": project_code, "year": year}


@router.get("/projects/{project_code}/trends")
def project_trends(
    project_code: str,
    user: dict = Depends(check_project_permission("co2", "view", "project_code", require_exists=False)),
) -> dict:
    with get_connection("co2") as conn:
        proj = conn.execute(
            """
            SELECT project_code, organization, project_name, life_span, emission_results, calculation_method, amp_before, amp_after
            FROM projects
            WHERE project_code = ?
            """,
            (project_code,),
        ).fetchone()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        _assert_project_row_scope(user, proj["organization"])

        tracking_rows = conn.execute(
            """
            SELECT year_number, section_type, row_index, absolute_value, specific_value
            FROM project_actuals
            WHERE project_code = ?
            ORDER BY year_number, section_type, row_index
            """,
            (project_code,),
        ).fetchall()
        amp_rows = conn.execute(
            """
            SELECT year_number, amp_value
            FROM amp_actuals_tracking
            WHERE project_code = ?
            ORDER BY year_number
            """,
            (project_code,),
        ).fetchall()

    emission_results = json.loads(proj["emission_results"] or "{}")
    baseline_abs = float(emission_results.get("Net CO2_Before", 0.0))
    target_abs = float(emission_results.get("Net CO2_After", 0.0))
    baseline_spec = float(emission_results.get("Sp.Net_Before", 0.0))
    target_spec = float(emission_results.get("Sp.Net_After", 0.0))

    amp_by_year = {int(r["year_number"]): float(r["amp_value"] or 0.0) for r in amp_rows if r["year_number"] is not None}
    year_net_abs: dict[int, float] = {}
    year_net_spec: dict[int, float] = {}

    year_input_abs: dict[int, float] = {}
    year_output_abs: dict[int, float] = {}
    year_input_spec: dict[int, float] = {}
    year_output_spec: dict[int, float] = {}

    for row in tracking_rows:
        year = int(row["year_number"])
        abs_val = float(row["absolute_value"] or 0.0)
        spec_val = float(row["specific_value"] or 0.0)
        if row["section_type"] == "input":
            year_input_abs[year] = year_input_abs.get(year, 0.0) + abs_val
            year_input_spec[year] = year_input_spec.get(year, 0.0) + spec_val
        else:
            year_output_abs[year] = year_output_abs.get(year, 0.0) + abs_val
            year_output_spec[year] = year_output_spec.get(year, 0.0) + spec_val

    all_years = sorted({*year_input_abs.keys(), *year_output_abs.keys(), *year_input_spec.keys(), *year_output_spec.keys()})
    for year in all_years:
        net_abs = year_input_abs.get(year, 0.0) - year_output_abs.get(year, 0.0)
        year_net_abs[year] = net_abs

        # Specific: if amp exists, convert absolute net using amp; else fall back to specific delta
        amp = amp_by_year.get(year, 0.0)
        if amp:
            year_net_spec[year] = net_abs / amp
        else:
            year_net_spec[year] = year_input_spec.get(year, 0.0) - year_output_spec.get(year, 0.0)

    abs_trend = [
        {"label": "Previous", "value": baseline_abs, "type": "previous"},
        {"label": "Target", "value": target_abs, "type": "target"},
    ] + [
        {"label": f"Actual Y{year}", "value": year_net_abs[year], "type": "actual", "year_number": year}
        for year in sorted(year_net_abs.keys())
    ]

    specific_trend = [
        {"label": "Previous", "value": baseline_spec, "type": "previous"},
        {"label": "Target", "value": target_spec, "type": "target"},
    ] + [
        {"label": f"Actual Y{year}", "value": year_net_spec[year], "type": "actual", "year_number": year}
        for year in sorted(year_net_spec.keys())
    ]

    return {
        "project_code": project_code,
        "project_name": proj["project_name"],
        "absolute_trend": abs_trend,
        "specific_trend": specific_trend,
    }
