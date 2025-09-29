import os
from typing import Dict, List
from dotenv import load_dotenv

# Load .env file only if running locally
if os.getenv("CI") != "true":  # GitHub Actions sets CI=true
    load_dotenv()

# ---------------------------
# Core connection
# ---------------------------
API_URL  = os.getenv("API_URL", "https://api.prod.alltrue-be.com").rstrip("/")
API_KEY  = os.getenv("API_KEY", "")
CUSTOMER_ID = os.getenv("CUSTOMER_ID", "")

if not all([API_URL, API_KEY, CUSTOMER_ID]):
    raise ValueError("Missing one or more required endpoint environment variables.")

LOG_JWT_THREADS = os.getenv("LOG_JWT_THREADS", "false").lower() == "true"

def _split_csv(name: str) -> List[str]:
    val = os.getenv(name, "")
    return [s.strip() for s in val.split(",") if s.strip()]

# ---------------------------
# Inventory selection
# ---------------------------
INVENTORY_SCOPE = os.getenv("INVENTORY_SCOPE", "organization")  # organization|project|resource
ORGANIZATION_ID = os.getenv("ORGANIZATION_ID") or None
PROJECT_IDS: List[str] = _split_csv("PROJECT_IDS")
TARGET_RESOURCE_IDS: List[str] = [s.lower() for s in _split_csv("TARGET_RESOURCE_IDS")]
TARGET_RESOURCE_NAMES: List[str] = _split_csv("TARGET_RESOURCE_NAMES")

HAS_VALID_PENTEST_CONNECTION_DETAILS = os.getenv("HAS_VALID_PENTEST_CONNECTION_DETAILS", "true").lower() == "true"

# ---------------------------
# Pentest run parameters
# ---------------------------
TARGET_TEMPLATE_NAME = os.getenv("TARGET_TEMPLATE_NAME", "Default LLM Pentest")
MAX_CONCURRENT_PENTESTS = int(os.getenv("MAX_CONCURRENT_PENTESTS", "5"))

# Optional stagger between start requests (seconds)
START_STAGGER_SECS = float(os.getenv("START_STAGGER_SECS", "0"))

# Start retry behavior for start-pentest failures classified as retryable
MAX_START_RETRIES = int(os.getenv("MAX_START_RETRIES", "3"))
START_RETRY_DELAY = float(os.getenv("START_RETRY_DELAY", "30"))

# Polling behavior
POLL_INTERVAL_SECS = float(os.getenv("POLL_INTERVAL_SECS", "10"))
POLL_TIMEOUT_SECS = float(os.getenv("POLL_TIMEOUT_SECS", "4200"))  # 70 minutes
POLL_BACKOFF_BASE_SECS = float(os.getenv("POLL_BACKOFF_BASE_SECS", "2"))
POLL_BACKOFF_MAX_SECS  = float(os.getenv("POLL_BACKOFF_MAX_SECS", "60"))
POLL_NOT_FOUND_GRACE   = int(os.getenv("POLL_NOT_FOUND_GRACE", "3"))
POLL_STATUS_LOG_EVERY  = int(os.getenv("POLL_STATUS_LOG_EVERY", "6"))
POLL_TIMEOUT_ACTION    = os.getenv("POLL_TIMEOUT_ACTION", "fail")  # fail|continue|partial

# Allow a one-time alternate job-status poll without X-API-Key after 401/403
JOB_STATUS_RETRY_WITHOUT_API_KEY = os.getenv("JOB_STATUS_RETRY_WITHOUT_API_KEY", "false").lower() == "true"

# Extended GraphQL polling after HTTP polling timeout (only if last status was RUNNING)
GRAPHQL_EXTENDED_TIMEOUT_SECS = float(os.getenv("GRAPHQL_EXTENDED_TIMEOUT_SECS", "1800"))
GRAPHQL_POLL_INTERVAL_SECS    = float(os.getenv("GRAPHQL_POLL_INTERVAL_SECS", "120"))

# ---------------------------
# Outcome thresholding
# ---------------------------
# Lower index means more severe
SEVERITY_ORDER = ["Critical", "Poor", "Moderate", "Good", "Excellent"]
SEVERITY_INDEX: Dict[str, int] = {name.lower(): i for i, name in enumerate(SEVERITY_ORDER)}

def normalize_outcome(level: str | None) -> str:
    """Return a canonical outcome ('critical'|'poor'|'moderate'|'good'|'excellent') or '' if unknown."""
    if not level:
        return ""
    s = level.strip().lower()
    return s if s in {"critical", "poor", "moderate", "good", "excellent"} else ""

# Fail the job if worst KNOWN outcome is at/above this threshold (set empty to ignore outcomes)
FAIL_OUTCOME_AT_OR_ABOVE = os.getenv("FAIL_OUTCOME_AT_OR_ABOVE", "").strip()  # e.g., "moderate"

# --- GitHub integration / end-of-run actions ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "")  # "owner/repo"

# What to do when outcomes breach the threshold:
#   - "fail"  : fail pipeline only
#   - "issue" : open GH issues only
#   - "both"  : fail AND open GH issues
#   - "none"  : do nothing
ON_THRESHOLD_ACTION = os.getenv("ON_THRESHOLD_ACTION", "fail").strip().lower()

# What to do on hard failures (start errors, exceptions, etc.):
#   - "ignore" (default), "issue", "fail", "both"
ON_HARD_FAILURES_ACTION = os.getenv("ON_HARD_FAILURES_ACTION", "ignore").strip().lower()

# Optional issue cosmetics
GITHUB_DEFAULT_LABELS = [s.strip() for s in os.getenv("GITHUB_DEFAULT_LABELS", "pentest").split(",") if s.strip()]
GITHUB_ASSIGNEES = [s.strip() for s in os.getenv("GITHUB_ASSIGNEES", "").split(",") if s.strip()]

# ---------------------------
# Category severity filtering for per-category GitHub issues
# ---------------------------
# Order from most to least severe:
CATEGORY_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
CATEGORY_SEVERITY_INDEX: Dict[str, int] = {name: i for i, name in enumerate(CATEGORY_SEVERITY_ORDER)}

def normalize_category_severity(s: str | None) -> str:
    """Return normalized category severity (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL) or '' if unknown."""
    if not s:
        return ""
    up = s.strip().upper()
    return up if up in CATEGORY_SEVERITY_INDEX else ""

# Minimum category severity to create per-category GitHub issues.
# Default "INFORMATIONAL" (creates for all severities).
CATEGORY_ISSUE_MIN_SEVERITY = normalize_category_severity(
    os.getenv("CATEGORY_ISSUE_MIN_SEVERITY", "INFORMATIONAL")
)

def print_config_banner() -> None:
    print("=" * 80)
    print("CONFIG")
    print("=" * 80)
    print(f"API_URL: {API_URL}")
    print(f"CUSTOMER_ID set: {'yes' if CUSTOMER_ID else 'no'}")
    print(f"INVENTORY_SCOPE: {INVENTORY_SCOPE}")
    if ORGANIZATION_ID:
        print(f"ORGANIZATION_ID: {ORGANIZATION_ID}")
    if PROJECT_IDS:
        print(f"PROJECT_IDS: {PROJECT_IDS}")
    if TARGET_RESOURCE_IDS or TARGET_RESOURCE_NAMES:
        print(f"TARGET_RESOURCE_IDS: {TARGET_RESOURCE_IDS}")
        print(f"TARGET_RESOURCE_NAMES: {TARGET_RESOURCE_NAMES}")
    print(f"HAS_VALID_PENTEST_CONNECTION_DETAILS: {HAS_VALID_PENTEST_CONNECTION_DETAILS}")
    print(f"TARGET_TEMPLATE_NAME: {TARGET_TEMPLATE_NAME}")
    print(f"MAX_CONCURRENT_PENTESTS: {MAX_CONCURRENT_PENTESTS}")
    if START_STAGGER_SECS:
        print(f"START_STAGGER_SECS: {START_STAGGER_SECS}")
    print(f"POLL_INTERVAL_SECS: {POLL_INTERVAL_SECS}  POLL_TIMEOUT_SECS: {POLL_TIMEOUT_SECS}")
    print(f"GRAPHQL_EXTENDED_TIMEOUT_SECS: {GRAPHQL_EXTENDED_TIMEOUT_SECS}")
    print(f"JOB_STATUS_RETRY_WITHOUT_API_KEY: {JOB_STATUS_RETRY_WITHOUT_API_KEY}")
    if FAIL_OUTCOME_AT_OR_ABOVE:
        print(f"FAIL_OUTCOME_AT_OR_ABOVE: {FAIL_OUTCOME_AT_OR_ABOVE}")
    else:
        print("FAIL_OUTCOME_AT_OR_ABOVE: (none)")
    print(f"ON_THRESHOLD_ACTION: {ON_THRESHOLD_ACTION}")
    print(f"ON_HARD_FAILURES_ACTION: {ON_HARD_FAILURES_ACTION}")
    # GitHub integration presence (no secrets printed)
    print(f"GITHUB_REPOSITORY: {GITHUB_REPOSITORY or '(not set)'}")
    print(f"GITHUB_TOKEN set: {'yes' if GITHUB_TOKEN else 'no'}")
    print(f"CATEGORY_ISSUE_MIN_SEVERITY: {CATEGORY_ISSUE_MIN_SEVERITY or '(none)'}")
    if GITHUB_DEFAULT_LABELS:
        print(f"GITHUB_DEFAULT_LABELS: {GITHUB_DEFAULT_LABELS}")
    if GITHUB_ASSIGNEES:
        print(f"GITHUB_ASSIGNEES: {GITHUB_ASSIGNEES}")
    print("=" * 80)