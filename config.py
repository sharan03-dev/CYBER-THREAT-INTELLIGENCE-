"""Central configuration. Every value can be overridden in the project-root .env file."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]          # .../cti-platform
load_dotenv(ROOT / ".env")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "cti_platform")          # the CTI platform (dumped for Lab 7.1)
LAB72_DB = os.getenv("LAB72_DB", "cti_lab72")            # 100k-document working-set test (Lab 7.2)
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

# Optional API keys - the platform works without any of them.
GREYNOISE_KEY = os.getenv("GREYNOISE_API_KEY", "").strip()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
OTX_KEY = os.getenv("OTX_API_KEY", "").strip()

IPSUM_MIN_HITS = int(os.getenv("IPSUM_MIN_HITS", "2"))   # keep IPs listed on >= N blacklists
NEWS_ITEMS_PER_FEED = int(os.getenv("NEWS_ITEMS_PER_FEED", "40"))
LOOKUP_CACHE_HOURS = float(os.getenv("LOOKUP_CACHE_HOURS", "6"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
USER_AGENT = os.getenv(
    "USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) CTI-Platform-Student/1.0 (educational project)",
)

FRONTEND_DIR = ROOT / "frontend"
DATA_DIR = ROOT / "backend" / "data"
BSON_LIMIT = 16 * 1024 * 1024  # 16 MB = 16,777,216 bytes
