from pydantic import BaseModel, Field


class NpvRequest(BaseModel):
    rate: float
    cashflows: list[float]


class MaccProjectUpsertRequest(BaseModel):
    id: str
    organization: str = ""
    entity_name: str = ""
    unit_name: str = ""
    project_name: str = ""
    base_year: str = ""
    target_year: str = ""
    implementation_date: str = ""
    life_span: str = "10"
    project_owner: str = ""
    initiative: str = ""
    industry: str = ""
    country: str = ""
    year: str = ""
    material_energy_data: dict = Field(default_factory=dict)
    option1_data: dict = Field(default_factory=dict)
    option2_data: dict = Field(default_factory=dict)
    result: dict = Field(default_factory=dict)
    npv1: float = 0.0
    npv2: float = 0.0
    mac: float = 0.0
    total_co2_diff: float = 0.0


class MaccEvaluateRequest(BaseModel):
    option1_discount_rate: float = 8.0
    option1_cashflows: list[float] = Field(default_factory=list)
    option2_discount_rate: float = 8.0
    option2_cashflows: list[float] = Field(default_factory=list)
    total_co2_diff: float = 0.0

