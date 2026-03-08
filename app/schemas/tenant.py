from pydantic import BaseModel


class TenantContextResponse(BaseModel):
    scope: str
    host: str
    organization_id: int | None = None
    organization_slug: str = ""