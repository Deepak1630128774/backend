from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection, row_to_dict, rows_to_dicts
from ..schemas.fuel import FuelCalculationSaveRequest, FuelSummaryRequest, FuelYearDataUpsertRequest
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

router = APIRouter(prefix="/api/fuel-energy", tags=["fuel-energy"], dependencies=[Depends(require_org_member_or_owner)])


def _scoped_organization_name(user: dict) -> str | None:
    name = str(user.get("selected_organization_name") or user.get("effective_organization_name") or "").strip()
    return name or None


def _assert_calculation_scope(user: dict, organization_name: str | None) -> None:
    scoped_name = _scoped_organization_name(user)
    if get_effective_role(user) in {"owner", "super_admin"} and not scoped_name:
        raise HTTPException(status_code=404, detail="Calculation not found")
    if not scoped_name:
        return
    normalized_scope = " ".join(scoped_name.lower().split())
    normalized_value = " ".join(str(organization_name or "").strip().lower().split())
    if normalized_scope != normalized_value:
        raise HTTPException(status_code=404, detail="Calculation not found")

DEFAULT_MATERIALS = [
    "Coal",
    "Natural Gas",
    "Electricity",
    "Diesel",
    "Gasoline",
    "LPG",
    "Biomass",
    "Steam",
    "Waste",
    "Renewable Energy",
    "Carbon Credits",
    "Logistics",
]


@router.get("/calculations")
def list_calculations(user: dict = Depends(check_module_permission("fuel", "view"))) -> list[dict]:
    with get_connection("strategy") as acl_conn:
        registry_rows = list_acl_projects(acl_conn, module_key="fuel", user=user)
    unique_codes = [str(row["external_project_id"]) for row in registry_rows]
    if not unique_codes:
        return []

    with get_connection("fuel") as conn:
        placeholders = ",".join("?" for _ in unique_codes)
        rows = conn.execute(
            f"""
            SELECT unique_code, org_name, entity_name, unit_name, project_owner, sector, baseline_year, previous_year, target_year, created_at
            FROM calculations
            WHERE unique_code IN ({placeholders})
            ORDER BY created_at DESC
            """,
            tuple(unique_codes),
        ).fetchall()
    items = {str(item["unique_code"]): item for item in rows_to_dicts(rows)}
    return [items[unique_code] for unique_code in unique_codes if unique_code in items]


@router.get("/calculations/{unique_code}")
def get_calculation(
    unique_code: str,
    user: dict = Depends(check_project_permission("fuel", "view", "unique_code", require_exists=False)),
) -> dict:
    with get_connection("fuel") as conn:
        calc_row = conn.execute(
            "SELECT * FROM calculations WHERE unique_code = ?", (unique_code,)
        ).fetchone()
        if not calc_row:
            raise HTTPException(status_code=404, detail="Calculation not found")
        _assert_calculation_scope(user, calc_row["org_name"])
        calc_id = calc_row["id"]

        baseline_rows = conn.execute(
            """
            SELECT scope, name, uom, quantity, ef, emission, energy_factor,
                   energy_factor_uom AS energy_uom, energy, row_num
            FROM materials_baseline
            WHERE calculation_id = ?
            ORDER BY row_num
            """,
            (calc_id,),
        ).fetchall()

        reduction_rows = conn.execute(
            "SELECT scope, reduction_pct FROM emission_reductions WHERE calculation_id = ?",
            (calc_id,),
        ).fetchall()

        base_value_rows = conn.execute(
            "SELECT scope, value FROM base_value_details WHERE calculation_id = ?",
            (calc_id,),
        ).fetchall()

    reductions_pct = {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}
    for row in reduction_rows:
        if row["scope"] in reductions_pct:
            reductions_pct[row["scope"]] = float(row["reduction_pct"] or 0.0) * 100

    baseline_input = {"1": 0.0, "2": 0.0, "3": 0.0}
    for row in base_value_rows:
        scope_num = row["scope"].replace("Scope ", "")
        if scope_num in baseline_input:
            baseline_input[scope_num] = float(row["value"] or 0.0)

    return {
        "meta": row_to_dict(calc_row),
        "baseline_rows": [dict(row) for row in baseline_rows],
        "reductions_pct": reductions_pct,
        "baseline_input": baseline_input,
    }


@router.post("/calculations")
def upsert_calculation(
    payload: FuelCalculationSaveRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    resolved_organization_name = _scoped_organization_name(user) or str(payload.org_name or "").strip()

    with get_connection("fuel") as conn:
        existing = conn.execute(
            "SELECT unique_code FROM calculations WHERE unique_code = ?",
            (payload.unique_code,),
        ).fetchone()

    with get_connection("strategy") as acl_conn:
        assert_payload_organization_access(acl_conn, user=user, organization_name=resolved_organization_name)
        if existing:
            assert_project_permission(
                acl_conn,
                user=user,
                module_key="fuel",
                external_project_id=payload.unique_code,
                action="edit",
                require_exists=False,
            )
        else:
            assert_module_permission(
                acl_conn,
                user=user,
                module_key="fuel",
                action="create",
            )
        ensure_project_registry(
            acl_conn,
            module_key="fuel",
            external_project_id=payload.unique_code,
            project_name=payload.unique_code,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )

    with get_connection("fuel") as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO calculations
            (unique_code, org_name, entity_name, unit_name, project_owner, sector, baseline_year, previous_year, target_year,
             baseline_production, previous_year_production, growth_rate, target_production)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.unique_code,
                resolved_organization_name,
                payload.entity_name,
                payload.unit_name,
                payload.project_owner,
                payload.sector,
                payload.baseline_year,
                payload.previous_year,
                payload.target_year,
                payload.baseline_production,
                payload.previous_year_production,
                payload.growth_rate,
                payload.target_production,
            ),
        )
        calc_id = cursor.execute(
            "SELECT id FROM calculations WHERE unique_code = ?", (payload.unique_code,)
        ).fetchone()["id"]

        cursor.execute("DELETE FROM materials_baseline WHERE calculation_id = ?", (calc_id,))
        for row_num, row in enumerate(payload.materials_baseline):
            cursor.execute(
                """
                INSERT INTO materials_baseline
                (calculation_id, row_num, scope, name, uom, quantity, ef, emission,
                 energy_factor, energy_factor_uom, energy)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    calc_id,
                    row_num,
                    row.scope,
                    row.name,
                    row.uom,
                    row.quantity,
                    row.ef,
                    row.emission,
                    row.energy_factor,
                    row.energy_uom,
                    row.energy,
                ),
            )

        cursor.execute("DELETE FROM emission_reductions WHERE calculation_id = ?", (calc_id,))
        for scope, pct in payload.reductions.items():
            normalized = pct / 100 if pct > 1 else pct
            cursor.execute(
                """
                INSERT INTO emission_reductions (calculation_id, scope, reduction_pct)
                VALUES (?, ?, ?)
                """,
                (calc_id, scope, normalized),
            )

        cursor.execute("DELETE FROM base_value_details WHERE calculation_id = ?", (calc_id,))
        if payload.base_emissions:
            for scope_key, value in payload.base_emissions.items():
                if value:
                    cursor.execute(
                        """
                        INSERT INTO base_value_details (calculation_id, scope, value)
                        VALUES (?, ?, ?)
                        """,
                        (calc_id, scope_key, value),
                    )

    return {"status": "ok", "unique_code": payload.unique_code}


@router.delete("/calculations/{unique_code}")
def delete_calculation(
    unique_code: str,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_project_permission(
            acl_conn,
            user=user,
            module_key="fuel",
            external_project_id=unique_code,
            action="delete",
            require_exists=False,
        )
    with get_connection("fuel") as conn:
        calc_row = conn.execute(
            "SELECT id, org_name FROM calculations WHERE unique_code = ?", (unique_code,)
        ).fetchone()
        if not calc_row:
            raise HTTPException(status_code=404, detail="Calculation not found")
        _assert_calculation_scope(user, calc_row["org_name"])
        calc_id = calc_row["id"]
        conn.execute("DELETE FROM materials_baseline WHERE calculation_id = ?", (calc_id,))
        conn.execute("DELETE FROM emission_reductions WHERE calculation_id = ?", (calc_id,))
        conn.execute("DELETE FROM base_value_details WHERE calculation_id = ?", (calc_id,))
        conn.execute("DELETE FROM calculations WHERE id = ?", (calc_id,))
    with get_connection("strategy") as acl_conn:
        module = acl_conn.execute("SELECT id FROM modules WHERE module_key = 'fuel'").fetchone()
        if module:
            acl_conn.execute(
                "DELETE FROM projects WHERE module_id = ? AND external_project_id = ?",
                (module["id"], unique_code),
            )
    return {"status": "deleted", "unique_code": unique_code}


@router.get("/materials")
def get_materials(_: dict = Depends(check_module_permission("fuel", "view"))) -> list[str]:
    materials = set(DEFAULT_MATERIALS)
    with get_connection("fuel") as conn:
        rows = conn.execute(
            "SELECT DISTINCT name FROM materials_baseline WHERE name IS NOT NULL AND name != ''"
        ).fetchall()
        materials.update([row["name"] for row in rows if row["name"]])

        table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='materials_target'"
        ).fetchone()
        if table_exists:
            rows_target = conn.execute(
                "SELECT DISTINCT name FROM materials_target WHERE name IS NOT NULL AND name != ''"
            ).fetchall()
            materials.update([row["name"] for row in rows_target if row["name"]])

    return sorted(materials)


@router.post("/summary")
def calculate_summary(
    payload: FuelSummaryRequest,
    _: dict = Depends(check_module_permission("fuel", "evaluate")),
) -> dict:
    previous_by_scope = {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}
    energy_by_scope = {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}

    for row in payload.baseline_rows:
        previous_by_scope[row.scope] += float(row.emission or 0.0)
        energy_by_scope[row.scope] += float(row.energy or 0.0)

    if payload.same_year:
        baseline_by_scope = previous_by_scope.copy()
    else:
        baseline_by_scope = {
            "Scope 1": float(payload.baseline_input.get("1", 0.0)),
            "Scope 2": float(payload.baseline_input.get("2", 0.0)),
            "Scope 3": float(payload.baseline_input.get("3", 0.0)),
        }

    target_by_scope = {}
    for scope in previous_by_scope:
        reduction_pct = float(payload.reductions_pct.get(scope, 0.0))
        target_by_scope[scope] = baseline_by_scope[scope] * (1 - reduction_pct / 100)

    return {
        "previous_by_scope": previous_by_scope,
        "baseline_by_scope": baseline_by_scope,
        "target_by_scope": target_by_scope,
        "energy_by_scope": energy_by_scope,
        "totals": {
            "previous": sum(previous_by_scope.values()),
            "baseline": sum(baseline_by_scope.values()),
            "target": sum(target_by_scope.values()),
            "energy": sum(energy_by_scope.values()),
        },
    }


@router.put("/calculations/{unique_code}/yearly/{year_number}")
def upsert_yearly_fuel_data(
    unique_code: str,
    year_number: int,
    payload: FuelYearDataUpsertRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    if payload.unique_code != unique_code:
        raise HTTPException(status_code=400, detail="Unique code mismatch")
    if year_number != payload.year_number:
        raise HTTPException(status_code=400, detail="Year mismatch")

    with get_connection("strategy") as acl_conn:
        # Backfill registry for legacy records.
        ensure_project_registry(
            acl_conn,
            module_key="fuel",
            external_project_id=unique_code,
            project_name=unique_code,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="fuel",
            external_project_id=unique_code,
            sub_entity_key="yearly_data_rows",
            external_sub_entity_id="yearly_data_rows",
            action="edit",
            require_exists=False,
        )

    with get_connection("fuel") as conn:
        calc = conn.execute(
            "SELECT unique_code, org_name FROM calculations WHERE unique_code = ?",
            (unique_code,),
        ).fetchone()
        if not calc:
            raise HTTPException(status_code=404, detail="Calculation not found")
        _assert_calculation_scope(user, calc["org_name"])

        conn.execute(
            "DELETE FROM fuel_yearly_data WHERE unique_code = ? AND year_number = ?",
            (unique_code, year_number),
        )

        for idx, row in enumerate(payload.rows):
            emission = float(row.quantity or 0.0) * float(row.ef or 0.0)
            energy = float(row.quantity or 0.0) * float(row.energy_factor or 0.0)
            conn.execute(
                """
                INSERT INTO fuel_yearly_data
                (unique_code, year_number, row_num, material, scope, uom, quantity, ef, emission,
                 energy_factor, energy_factor_uom, energy, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    unique_code,
                    year_number,
                    idx,
                    row.material,
                    row.scope,
                    row.uom,
                    row.quantity,
                    row.ef,
                    emission,
                    row.energy_factor,
                    row.energy_uom,
                    energy,
                ),
            )

    return {"status": "ok", "unique_code": unique_code, "year_number": year_number}


@router.get("/calculations/{unique_code}/yearly/{year_number}")
def get_yearly_fuel_data(
    unique_code: str,
    year_number: int,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_sub_entity_permission(
            acl_conn,
            user=user,
            module_key="fuel",
            external_project_id=unique_code,
            sub_entity_key="yearly_data_rows",
            external_sub_entity_id="yearly_data_rows",
            action="view",
            require_exists=False,
        )
    with get_connection("fuel") as conn:
        calc = conn.execute(
            "SELECT org_name FROM calculations WHERE unique_code = ?",
            (unique_code,),
        ).fetchone()
        if calc:
            _assert_calculation_scope(user, calc["org_name"])
        rows = conn.execute(
            """
            SELECT material, scope, uom, quantity, ef, emission, energy_factor, energy_factor_uom, energy
            FROM fuel_yearly_data
            WHERE unique_code = ? AND year_number = ?
            ORDER BY row_num
            """,
            (unique_code, year_number),
        ).fetchall()
    return {"unique_code": unique_code, "year_number": year_number, "rows": rows_to_dicts(rows)}


@router.get("/calculations/{unique_code}/trends")
def get_emission_trends(
    unique_code: str,
    user: dict = Depends(check_project_permission("fuel", "view", "unique_code", require_exists=False)),
) -> dict:
    with get_connection("fuel") as conn:
        calc = conn.execute(
            """
            SELECT unique_code, org_name, baseline_year, previous_year, target_year
            FROM calculations WHERE unique_code = ?
            """,
            (unique_code,),
        ).fetchone()
        if not calc:
            raise HTTPException(status_code=404, detail="Calculation not found")
        _assert_calculation_scope(user, calc["org_name"])

        base_rows = conn.execute(
            """
            SELECT scope, SUM(COALESCE(emission, 0)) AS emission_total
            FROM materials_baseline
            WHERE calculation_id = (SELECT id FROM calculations WHERE unique_code = ?)
            GROUP BY scope
            """,
            (unique_code,),
        ).fetchall()

        reduction_rows = conn.execute(
            """
            SELECT scope, reduction_pct
            FROM emission_reductions
            WHERE calculation_id = (SELECT id FROM calculations WHERE unique_code = ?)
            """,
            (unique_code,),
        ).fetchall()

        yearly_rows = conn.execute(
            """
            SELECT year_number, SUM(COALESCE(emission, 0)) AS actual_emission
            FROM fuel_yearly_data
            WHERE unique_code = ?
            GROUP BY year_number
            ORDER BY year_number
            """,
            (unique_code,),
        ).fetchall()

        yearly_energy_mix = conn.execute(
            """
            SELECT year_number, material, SUM(COALESCE(energy, 0)) AS energy_total
            FROM fuel_yearly_data
            WHERE unique_code = ?
            GROUP BY year_number, material
            ORDER BY year_number, material
            """,
            (unique_code,),
        ).fetchall()

    baseline_total = sum(float(r["emission_total"] or 0.0) for r in base_rows)
    reduction_map = {r["scope"]: float(r["reduction_pct"] or 0.0) for r in reduction_rows}
    avg_reduction = 0.0
    if reduction_map:
        avg_reduction = sum(reduction_map.values()) / len(reduction_map)
    target_total = baseline_total * (1 - avg_reduction)

    trend = [
        {"label": "Previous", "value": baseline_total, "type": "previous"},
        {"label": "Target", "value": target_total, "type": "target"},
    ]
    trend.extend(
        [
            {
                "label": f"Actual Y{int(row['year_number'])}",
                "value": float(row["actual_emission"] or 0.0),
                "type": "actual",
                "year_number": int(row["year_number"]),
            }
            for row in yearly_rows
        ]
    )

    mix: dict[int, list[dict]] = {}
    for row in yearly_energy_mix:
        year_num = int(row["year_number"])
        mix.setdefault(year_num, []).append(
            {
                "material": row["material"],
                "energy_total": float(row["energy_total"] or 0.0),
            }
        )

    return {
        "unique_code": unique_code,
        "baseline_total": baseline_total,
        "target_total": target_total,
        "trend": trend,
        "energy_mix_by_year": [
            {"year_number": year, "items": items}
            for year, items in sorted(mix.items(), key=lambda x: x[0])
        ],
    }
