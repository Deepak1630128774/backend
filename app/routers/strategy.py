import json

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection, row_to_dict, rows_to_dicts
from ..schemas.strategy import StrategyAnalyzeRequest, StrategyPortfolioUpsertRequest
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

router = APIRouter(prefix="/api/strategy", tags=["strategy"], dependencies=[Depends(require_org_member_or_owner)])


def _normalize_name(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _scoped_organization_name(user: dict) -> str | None:
    name = str(user.get("selected_organization_name") or user.get("effective_organization_name") or "").strip()
    return name or None


def _assert_portfolio_scope(user: dict, organization_name: str | None) -> None:
    scoped_name = _scoped_organization_name(user)
    if get_effective_role(user) in {"owner", "super_admin"} and not scoped_name:
        raise HTTPException(status_code=404, detail="Portfolio not found")
    if not scoped_name:
        return
    normalized_scope = " ".join(scoped_name.lower().split())
    normalized_value = " ".join(str(organization_name or "").strip().lower().split())
    if normalized_scope != normalized_value:
        raise HTTPException(status_code=404, detail="Portfolio not found")


def _portfolio_name_exists_in_scope(*, portfolio_id: str, portfolio_name: str, organization_name: str, scope_organization_id: int | None) -> bool:
    normalized_portfolio_name = _normalize_name(portfolio_name)
    if not normalized_portfolio_name:
        return False

    with get_connection("strategy") as conn:
        if scope_organization_id is not None:
            module = conn.execute(
                "SELECT id FROM modules WHERE module_key = 'strategy' LIMIT 1"
            ).fetchone()
            if module:
                row = conn.execute(
                    """
                    SELECT sp.id
                    FROM strategy_portfolios sp
                    JOIN projects p ON p.external_project_id = sp.id AND p.module_id = ?
                    WHERE p.organization_id = ?
                        AND sp.id != ?
                        AND lower(trim(sp.name)) = lower(trim(?))
                    LIMIT 1
                    """,
                    (module["id"], scope_organization_id, portfolio_id, portfolio_name),
                ).fetchone()
                if row:
                    return True

        row = conn.execute(
            """
            SELECT id FROM strategy_portfolios
            WHERE lower(trim(name)) = lower(trim(?))
                AND lower(trim(COALESCE(organization, ''))) = lower(trim(?))
                AND id != ?
            LIMIT 1
            """,
            (portfolio_name, organization_name, portfolio_id),
        ).fetchone()
        return bool(row)


@router.get("/portfolios")
def list_portfolios(user: dict = Depends(check_module_permission("strategy", "view"))) -> list[dict]:
    with get_connection("strategy") as conn:
        registry_rows = list_acl_projects(conn, module_key="strategy", user=user)
    portfolio_ids = [str(row["external_project_id"]) for row in registry_rows]
    if not portfolio_ids:
        return []

    with get_connection("strategy") as conn:
        placeholders = ",".join("?" for _ in portfolio_ids)
        rows = conn.execute(
            f"""
            SELECT id, name, organization, sector, baseline_calc_id, selected_macc_projects, created_at, updated_at
            FROM strategy_portfolios
            WHERE id IN ({placeholders})
            ORDER BY created_at DESC
            """,
            tuple(portfolio_ids),
        ).fetchall()
    items = {str(row["id"]): row for row in rows_to_dicts(rows)}
    portfolios = [items[portfolio_id] for portfolio_id in portfolio_ids if portfolio_id in items]
    for row in portfolios:
        row["selected_macc_projects"] = (
            json.loads(row["selected_macc_projects"]) if row["selected_macc_projects"] else []
        )
    return portfolios


@router.get("/portfolios/{portfolio_id}")
def get_portfolio(
    portfolio_id: str,
    user: dict = Depends(check_project_permission("strategy", "view", "portfolio_id", require_exists=False)),
) -> dict:
    with get_connection("strategy") as conn:
        row = conn.execute(
            "SELECT * FROM strategy_portfolios WHERE id = ?",
            (portfolio_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Portfolio not found")
    _assert_portfolio_scope(user, row["organization"])
    data = row_to_dict(row)
    data["selected_macc_projects"] = (
        json.loads(data["selected_macc_projects"]) if data.get("selected_macc_projects") else []
    )
    return data


@router.post("/portfolios")
def upsert_portfolio(
    payload: StrategyPortfolioUpsertRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    resolved_organization_name = _scoped_organization_name(user) or str(payload.organization or "").strip()

    with get_connection("strategy") as acl_conn:
        assert_payload_organization_access(acl_conn, user=user, organization_name=resolved_organization_name)
        existing = acl_conn.execute(
            """
            SELECT p.id
            FROM projects p
            JOIN modules m ON m.id = p.module_id
            WHERE m.module_key = 'strategy' AND p.external_project_id = ?
            """,
            (payload.id,),
        ).fetchone()
        if existing:
            assert_project_permission(
                acl_conn,
                user=user,
                module_key="strategy",
                external_project_id=payload.id,
                action="edit",
                require_exists=False,
            )
        else:
            assert_module_permission(acl_conn, user=user, module_key="strategy", action="create")

        ensure_project_registry(
            acl_conn,
            module_key="strategy",
            external_project_id=payload.id,
            project_name=payload.name,
            creator_user_id=int(user["id"]),
            organization_id=get_data_scope_organization_id(user),
        )
        for sub_key in ("macc_selections", "portfolio_snapshots"):
            assert_sub_entity_permission(
                acl_conn,
                user=user,
                module_key="strategy",
                external_project_id=payload.id,
                sub_entity_key=sub_key,
                external_sub_entity_id=sub_key,
                action="edit",
                require_exists=False,
            )

    if _portfolio_name_exists_in_scope(
        portfolio_id=payload.id,
        portfolio_name=payload.name.strip(),
        organization_name=resolved_organization_name,
        scope_organization_id=get_data_scope_organization_id(user),
    ):
        raise HTTPException(status_code=409, detail="Portfolio name already exists")

    with get_connection("strategy") as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO strategy_portfolios
            (id, name, organization, sector, baseline_calc_id, selected_macc_projects, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                payload.id,
                payload.name.strip(),
                resolved_organization_name,
                payload.sector,
                payload.baseline_calc_id,
                json.dumps(payload.selected_macc_projects),
            ),
        )

    return {"status": "ok", "id": payload.id}


@router.delete("/portfolios/{portfolio_id}")
def delete_portfolio(
    portfolio_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_project_permission(
            acl_conn,
            user=user,
            module_key="strategy",
            external_project_id=portfolio_id,
            action="delete",
            require_exists=False,
        )
    with get_connection("strategy") as conn:
        row = conn.execute(
            "SELECT id, organization FROM strategy_portfolios WHERE id = ?",
            (portfolio_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Portfolio not found")
        _assert_portfolio_scope(user, row["organization"])
        conn.execute("DELETE FROM strategy_portfolios WHERE id = ?", (portfolio_id,))
    with get_connection("strategy") as conn:
        module = conn.execute("SELECT id FROM modules WHERE module_key = 'strategy'").fetchone()
        if module:
            conn.execute(
                "DELETE FROM projects WHERE module_id = ? AND external_project_id = ?",
                (module["id"], portfolio_id),
            )
    return {"status": "deleted", "id": portfolio_id}


@router.post("/analyze")
def analyze(
    payload: StrategyAnalyzeRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as acl_conn:
        assert_module_permission(acl_conn, user=user, module_key="strategy", action="evaluate")
        # Baseline and selected MACC projects must be readable for this user.
        assert_project_permission(
            acl_conn,
            user=user,
            module_key="fuel",
            external_project_id=payload.baseline_calc_id,
            action="view",
            require_exists=False,
        )
        for project_id in payload.selected_macc_projects:
            assert_project_permission(
                acl_conn,
                user=user,
                module_key="macc",
                external_project_id=project_id,
                action="view",
                require_exists=False,
            )

    years = max(1, min(payload.years, 50))

    with get_connection("fuel") as conn_fuel:
        calc_row = conn_fuel.execute(
            "SELECT unique_code, org_name, sector FROM calculations WHERE unique_code = ?",
            (payload.baseline_calc_id,),
        ).fetchone()
        if not calc_row:
            raise HTTPException(status_code=404, detail="Baseline calculation not found")

        calc_id_row = conn_fuel.execute(
            "SELECT id FROM calculations WHERE unique_code = ?",
            (payload.baseline_calc_id,),
        ).fetchone()
        calc_id = calc_id_row["id"]
        emissions = conn_fuel.execute(
            """
            SELECT scope, SUM(COALESCE(emission, 0)) AS total_emission
            FROM materials_baseline
            WHERE calculation_id = ?
            GROUP BY scope
            """,
            (calc_id,),
        ).fetchall()

    baseline_by_scope = {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}
    for row in emissions:
        if row["scope"] in baseline_by_scope:
            baseline_by_scope[row["scope"]] = float(row["total_emission"] or 0.0)
    baseline_total = sum(baseline_by_scope.values())

    selected_projects: list[dict] = []
    if payload.selected_macc_projects:
        placeholders = ",".join("?" for _ in payload.selected_macc_projects)
        with get_connection("npv") as conn_npv:
            rows = conn_npv.execute(
                f"""
                SELECT id, project_name, organization, mac, total_co2_diff
                FROM npv_projects
                WHERE id IN ({placeholders})
                """,
                tuple(payload.selected_macc_projects),
            ).fetchall()
        selected_projects = rows_to_dicts(rows)

    annual_abatement = sum(max(float(row.get("total_co2_diff") or 0.0), 0.0) for row in selected_projects)
    pathway = [{"year": 0, "emission": baseline_total}]
    for year in range(1, years + 1):
        remaining = max(baseline_total - annual_abatement * year, 0.0)
        pathway.append({"year": year, "emission": remaining})

    macc_curve = sorted(
        [
            {
                "id": row.get("id"),
                "project_name": row.get("project_name") or row.get("id"),
                "mac": float(row.get("mac") or 0.0),
                "co2_reduction": float(row.get("total_co2_diff") or 0.0),
            }
            for row in selected_projects
        ],
        key=lambda x: x["mac"],
    )

    recommendations: list[str] = []
    if not selected_projects:
        recommendations.append("No MACC projects selected. Add projects to generate strategy scenarios.")
    else:
        low_cost = [p for p in macc_curve if p["mac"] <= 0]
        if low_cost:
            recommendations.append(
                f"Prioritize {len(low_cost)} no-regret project(s) with non-positive MAC for immediate rollout."
            )
        if annual_abatement > 0:
            years_to_zero = baseline_total / annual_abatement if annual_abatement else None
            if years_to_zero is not None:
                recommendations.append(
                    f"At current annual abatement, modeled time to net-zero scope total is about {years_to_zero:.1f} years."
                )
        if annual_abatement <= 0:
            recommendations.append("Current selected portfolio does not reduce emissions. Rebalance project mix.")

    return {
        "baseline": {
            "calc_id": calc_row["unique_code"],
            "organization": calc_row["org_name"],
            "sector": calc_row["sector"],
            "by_scope": baseline_by_scope,
            "total": baseline_total,
        },
        "portfolio": {
            "selected_count": len(selected_projects),
            "annual_abatement": annual_abatement,
        },
        "pathway": pathway,
        "macc_curve": macc_curve,
        "recommendations": recommendations,
    }
