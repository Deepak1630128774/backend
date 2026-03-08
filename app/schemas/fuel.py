from typing import Literal

from pydantic import BaseModel, Field

ScopeType = Literal["Scope 1", "Scope 2", "Scope 3"]


class BaselineRow(BaseModel):
    scope: ScopeType
    name: str = ""
    uom: str = "kg"
    quantity: float = 0.0
    ef: float = 0.0
    emission: float = 0.0
    energy_factor: float = 0.0
    energy_uom: str = "GJ"
    energy: float = 0.0


class FuelCalculationSaveRequest(BaseModel):
    unique_code: str
    org_name: str
    entity_name: str = ""
    unit_name: str = ""
    project_owner: str = ""
    sector: str
    baseline_year: int
    previous_year: int
    target_year: int
    baseline_production: float = 0.0
    previous_year_production: float = 0.0
    growth_rate: float = 0.0
    target_production: float = 0.0
    materials_baseline: list[BaselineRow]
    reductions: dict[ScopeType, float] = Field(
        default_factory=lambda: {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}
    )
    base_emissions: dict[str, float] | None = None


class FuelSummaryRequest(BaseModel):
    baseline_rows: list[BaselineRow]
    reductions_pct: dict[ScopeType, float] = Field(
        default_factory=lambda: {"Scope 1": 0.0, "Scope 2": 0.0, "Scope 3": 0.0}
    )
    baseline_input: dict[str, float] = Field(default_factory=lambda: {"1": 0.0, "2": 0.0, "3": 0.0})
    same_year: bool = True


class FuelYearEntry(BaseModel):
    material: str
    scope: ScopeType
    uom: str = "kg"
    quantity: float = 0.0
    ef: float = 0.0
    energy_factor: float = 0.0
    energy_uom: str = "GJ"


class FuelYearDataUpsertRequest(BaseModel):
    unique_code: str
    year_number: int
    rows: list[FuelYearEntry]
