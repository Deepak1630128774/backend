from pydantic import BaseModel, Field


class StrategyPortfolioUpsertRequest(BaseModel):
    id: str
    name: str
    organization: str
    sector: str
    baseline_calc_id: str
    selected_macc_projects: list[str] = Field(default_factory=list)


class StrategyAnalyzeRequest(BaseModel):
    baseline_calc_id: str
    selected_macc_projects: list[str] = Field(default_factory=list)
    years: int = 10

