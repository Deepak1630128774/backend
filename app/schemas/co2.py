from typing import Literal

from pydantic import BaseModel, Field

CalcMethod = Literal["absolute", "specific"]


class DataRow(BaseModel):
    material: str = ""
    uom: str = "kg"
    ef: float = 0.0
    abs_before: float = 0.0
    abs_after: float = 0.0
    spec_before: float = 0.0
    spec_after: float = 0.0


class CostingRow(BaseModel):
    parameter: str
    uom: str = "INR"
    before: float = 0.0
    after: float = 0.0


class Co2ProjectUpsertRequest(BaseModel):
    project_code: str
    organization: str
    entity_name: str
    unit_name: str
    project_name: str
    base_year: str
    target_year: str
    implementation_date: str
    capex: str | None = ""
    life_span: str = "10"
    project_owner: str
    input_data: list[dict] = Field(default_factory=list)
    output_data: list[dict] = Field(default_factory=list)
    costing_data: list[dict] = Field(default_factory=list)
    amp_before: float = 0.0
    amp_after: float = 0.0
    amp_uom: str = "t/tp"
    calculation_method: CalcMethod = "absolute"
    emission_results: dict | None = None
    costing_results: dict | None = None


class Co2CalculationRequest(BaseModel):
    method: CalcMethod = "absolute"
    input_data: list[DataRow] = Field(default_factory=list)
    output_data: list[DataRow] = Field(default_factory=list)
    costing_data: list[CostingRow] = Field(default_factory=list)
    amp_before: float = 0.0
    amp_after: float = 0.0
    primary_output_before: float = 0.0
    primary_output_after: float = 0.0


class TrackingInputRow(BaseModel):
    material_name: str
    row_index: int
    absolute_value: float | None = None
    specific_value: float | None = None


class TrackingSaveRequest(BaseModel):
    input_rows: list[TrackingInputRow] = Field(default_factory=list)
    output_rows: list[TrackingInputRow] = Field(default_factory=list)
    amp_value: float | None = None

