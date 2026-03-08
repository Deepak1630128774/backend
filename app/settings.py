import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE_FILE = ROOT_DIR / ".env.example"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
elif ENV_EXAMPLE_FILE.exists():
    # Fallback for local setups where only .env.example is populated.
    load_dotenv(ENV_EXAMPLE_FILE)

DB_PATH = ROOT_DIR / "npv_projects.db"
FUEL_DB_PATH = ROOT_DIR / "fuel_energy.db"
PROJECT_DB_PATH = ROOT_DIR / "co2_calculator.db"
STRATEGY_DB_PATH = ROOT_DIR / "strategy_dashboards.db"

API_JWT_SECRET = os.getenv("API_JWT_SECRET", "change-me-in-env")
API_JWT_ALGO = "HS256"
API_TOKEN_EXPIRE_MINUTES = int(os.getenv("API_TOKEN_EXPIRE_MINUTES", "480"))

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip().replace(" ", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER).strip()

OWNER_ALERT_EMAIL = os.getenv("OWNER_ALERT_EMAIL", "deepakbagam001@gmail.com")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8080")

BOOTSTRAP_OWNER_EMAIL = os.getenv("BOOTSTRAP_OWNER_EMAIL", "")
BOOTSTRAP_OWNER_PASSWORD = os.getenv("BOOTSTRAP_OWNER_PASSWORD", "")
BOOTSTRAP_OWNER_NAME = os.getenv("BOOTSTRAP_OWNER_NAME", "Website Owner")
