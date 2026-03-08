from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .init_db import init_databases
from .routers.admin import router as admin_router
from .routers.auth import router as auth_router
from .routers.co2 import router as co2_router
from .routers.fuel import router as fuel_router
from .routers.macc import router as macc_router
from .routers.org_admin import router as org_admin_router
from .routers.owner_admin import router as owner_admin_router
from .routers.public_auth import router as public_auth_router
from .routers.strategy import router as strategy_router
from .routers.tenant_auth import router as tenant_auth_router
from .settings import APP_BASE_URL

ALLOWED_ORIGINS = sorted(
    {
        APP_BASE_URL.rstrip("/"),
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    }
)


def _build_allowed_origin_regex() -> str:
    hostname = (urlparse(APP_BASE_URL).hostname or "").strip().lower()
    if not hostname:
        return r"^https?://([a-z0-9-]+\.)?localhost(?::\d+)?$"
    escaped = hostname.replace(".", r"\.")
    patterns = [rf"https?://([a-z0-9-]+\.)?{escaped}(?::\d+)?"]
    if hostname != "localhost":
        patterns.append(r"https?://([a-z0-9-]+\.)?localhost(?::\d+)?")
    return rf"^({'|'.join(patterns)})$"


ALLOWED_ORIGIN_REGEX = _build_allowed_origin_regex()

app = FastAPI(
    title="Decarbonization API",
    version="1.0.0",
    description="Backend API for Fuel & Energy, CO2 Project, MACC, and Strategy modules.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_databases()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(fuel_router)
app.include_router(co2_router)
app.include_router(macc_router)
app.include_router(strategy_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(public_auth_router)
app.include_router(tenant_auth_router)
app.include_router(owner_admin_router)
app.include_router(org_admin_router)
