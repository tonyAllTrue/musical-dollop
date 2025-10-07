import re
import threading
from typing import Any, Dict, List, Optional, Callable, TypeVar
from datetime import datetime, timezone
import time as _t

import requests
import config
from utils import parse_csv_string


# ---------- Masking / HTTP core ----------

def _mask(s: str, show: int = 4) -> str:
    if not s:
        return s
    return s[:show] + "…" if len(s) > show else "…"


def make_api_request(
    endpoint: str,
    token: str,
    method: str = "GET",
    data: Any = None,
    params: Dict[str, Any] | None = None,
    include_api_key: bool = False,
    accept: str = "application/json",
    content_type: str | None = "application/json",
    timeout: int | float | None = None,
) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
    }
    if content_type:
        headers["Content-Type"] = content_type
    if include_api_key:
        headers["X-API-Key"] = config.API_KEY

    url = f"{config.API_URL}{endpoint}"
    resp = requests.request(method, url, headers=headers, params=params, json=data, timeout=timeout)
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        safe_headers = {k: (v if k.lower() not in {"authorization", "x-api-key"} else _mask(v))
                        for k, v in headers.items()}
        print(f"[-] {method} {url} failed: {resp.status_code}")
        print(f"    Headers sent: {safe_headers}")
        print(f"    Response: {resp.text}")
        raise
    return resp


# ---------- Shared utilities ----------

def sanitize_name(name: str) -> str:
    safe = "".join(c for c in name if c.isalnum() or c in (" ", "-", "_")).rstrip()
    safe = safe.replace(" ", "_")
    return re.sub(r"_+", "_", safe)


def download_results_csv(jwt_token: str, resource_name: str, resource_id: str, scan_execution_id: str) -> str | None:
    endpoint = f"/v2/llm-pentest/customer/{config.CUSTOMER_ID}/executions/{scan_execution_id}/download-csv"
    try:
        resp = make_api_request(
            endpoint,
            token=jwt_token,
            method="POST",
            accept="text/csv,application/octet-stream,*/*",
            content_type=None,
            timeout=60,
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = f"pentest_results_{sanitize_name(resource_name)}_{resource_id[:8]}_{scan_execution_id[:8]}_{ts}.csv"
        with open(fname, "wb") as f:
            f.write(resp.content)
        print(f"[Thread: {threading.current_thread().name}][+] CSV saved as {fname}")
        return fname
    except Exception as e:
        print(f"[Thread: {threading.current_thread().name}][-] Error downloading results: {e}")
        return None


# ---------- Generic GraphQL runner ----------

def run_graphql(jwt_token: str, query: str, variables: dict, *, version: str = "v2", timeout: int = 30) -> dict:
    """
    Generic GraphQL executor that returns the `data` object or raises on errors.
    Consolidates repeated POST + error handling logic used by bespoke query_* functions.
    """
    endpoint = f"/{version}/graphql"
    resp = make_api_request(
        endpoint,
        token=jwt_token,
        method="POST",
        data={"query": query, "variables": variables},
        accept="application/json",
        content_type="application/json",
        timeout=timeout,
    )
    payload = resp.json() or {}
    if "errors" in payload:
        raise RuntimeError(payload["errors"])
    return payload.get("data", {})


# ---------- v2 GraphQL: Pentest full execution ----------

def query_pentest_execution_full(jwt_token: str, scan_execution_id: str) -> dict:
    """
    Fetches execution, resource, and per-category results (passed/failed/inconclusive).
    """
    graphql_query = """
    query LlmPentestScanExecutionResults($customerId: UUID!, $llmPentestScanExecutionId: UUID!) {
      llmPentestScanExecution(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        startedAt
        outcomeLevel
        llmPentestScanExecutionId
        chosenLlmModel
      }
      resourceInstanceForLlmPentestScanExecution(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        displayName
        resourceInstanceId
      }
      failedCategoriesResultsPerCategory(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        llmPentestCustomerCategoryId
        severity
        categoryDisplayName
        totalTestCases
        passedTestCases
        failedTestCases
        failedTestCaseDetails {
          externalPrompt
          output
          failedReason
          llmPentestCustomerTestcaseId
        }
      }
    }"""
    data = run_graphql(
        jwt_token,
        graphql_query,
        {"customerId": config.CUSTOMER_ID, "llmPentestScanExecutionId": scan_execution_id},
        version="v2",
        timeout=60,
    )
    return data or {}


# ---------- v1 GraphQL: aiSpmGetPentestIssues ----------

def query_spm_pentest_issues(
    jwt_token: str,
    filters: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    """
    Call /v1/graphql -> aiSpmGetPentestIssues(filter: PentestIssueFilter!)
    Returns the list under data.aiSpmGetPentestIssues.pentestFindings.

    Args:
        jwt_token: JWT authentication token
        filters: Optional dict of filter parameters to apply. Supported keys:
            - organizationId: str
            - projectId: str
            - issueStatus: List[str] - ["UNRESOLVED","REMEDIATED","DISMISSED","ARCHIVED","OVERDUE"]
            - issueSeverities: List[str] - ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"]
            - resourceDisplayNames: List[str]
            - pentestFindings: List[str] - policy/category names, e.g. ["Prompt Injection"]

    Returns:
        List of pentest findings

    Note:
        PentestIssueFilter does NOT include llmPentestScanExecutionId; match exec IDs client-side.
        Default issueStatus is ["UNRESOLVED"] if not specified in filters.
    """
    query = """
    query PentestIssues($filter: PentestIssueFilter!) {
      aiSpmGetPentestIssues(filter: $filter) {
        pentestFindings {
          llmPentestScanExecutionId
          inProgress
          inProgressAt
          issueCreatedDate
          issueId
          issueType
          numProjects
          policyName
          projectNames
          resourceDisplayName
          resourceType
          resourceTypeDisplayName
          scanId
          severity
          status
        }
      }
    }"""

    # Start with required fields and defaults
    filter_obj: Dict[str, Any] = {
        "customerId": config.CUSTOMER_ID,
        "issueStatus": ["UNRESOLVED"],  # default status
    }

    # Merge in user-provided filters (overwrites defaults)
    if filters:
        filter_obj.update(filters)

    data = run_graphql(jwt_token, query, {"filter": filter_obj}, version="v1", timeout=45)
    wrapper = data.get("aiSpmGetPentestIssues") or {}
    findings = wrapper.get("pentestFindings") or []
    return findings if isinstance(findings, list) else []


# ---------- Inventory helpers ----------

def build_scope_filters(
    organization_id: Optional[str | list] = None,
    project_id: Optional[str | list] = None,
) -> Dict[str, Any]:
    """
    Build scope filter dict based on INVENTORY_SCOPE and the provided IDs.
    - Accepts singular or plural vars from args; falls back to config.* if absent.
    - When INVENTORY_SCOPE='resource', at least one of org/project must be provided.
    - Returns a NEW dict (no mutation).
    """
    scope = (getattr(config, "INVENTORY_SCOPE", "") or "").lower()

    # Collect from args first, then config (singular or plural)
    orgs = parse_csv_string(organization_id)
    if not orgs:
        orgs = parse_csv_string(getattr(config, "ORGANIZATION_ID", None)) or \
               parse_csv_string(getattr(config, "ORGANIZATION_IDS", None))

    projs = parse_csv_string(project_id)
    if not projs:
        projs = parse_csv_string(getattr(config, "PROJECT_ID", None)) or \
                parse_csv_string(getattr(config, "PROJECT_IDS", None))

    params: Dict[str, Any] = {}

    if scope == "resource":
        if not orgs and not projs:
            raise ValueError(
                "When INVENTORY_SCOPE='resource', an organization_id or project_id is required."
            )
        if orgs:
            params["organization"] = orgs if len(orgs) > 1 else orgs[0]
        if projs:
            params["project"] = projs if len(projs) > 1 else projs[0]
        return params

    # Non-resource scope: still respect explicit args if provided
    if orgs:
        params["organization"] = orgs if len(orgs) > 1 else orgs[0]
    if projs:
        params["project"] = projs if len(projs) > 1 else projs[0]
    return params


# ---------- Unified inventory + thin wrappers ----------

def list_resources(
    jwt_token: str,
    *,
    categories: List[str] | None = None,           # e.g., ["llm_endpoint"], ["model","model_assets"]
    organization_id: str | List[str] | None = None,
    project_id: str | List[str] | None = None,
    omit_not_ai: bool = True,
    valid_only: bool | None = None,                # applies to llm_endpoint category
    resource_instance_ids: List[str] | None = None,
    resource_display_names: List[str] | None = None,
) -> list[dict]:
    """
    Unified inventory call for all resource categories.
    - `categories` maps to 'resource_category' query param (list or scalar).
    - Scope filters handled by build_scope_filters (args preferred; config fallback).
    - For llm_endpoint, `valid_only=True` adds 'has_valid_pentest_connection_details'.
    - Optional direct filtering by resource_instance_id or resource_display_name.
    """
    params: Dict[str, Any] = {"omit_not_ai": omit_not_ai}
    if categories:
        params["resource_category"] = categories
    if valid_only is True:
        params["has_valid_pentest_connection_details"] = True
    if resource_instance_ids:
        params["resource_instance_id"] = resource_instance_ids if len(resource_instance_ids) > 1 else resource_instance_ids[0]
    if resource_display_names:
        params["resource_display_name"] = resource_display_names if len(resource_display_names) > 1 else resource_display_names[0]

    # Build scope filters and merge (no mutation in helper)
    params.update(build_scope_filters(organization_id=organization_id, project_id=project_id))

    endpoint = f"/v1/inventory/customer/{config.CUSTOMER_ID}/resources"
    resp = make_api_request(endpoint, token=jwt_token, method="GET", params=params)
    return resp.json().get("resources", [])


def list_llm_endpoints(
    jwt_token: str,
    organization_id: str | None = None,
    project_id: str | None = None,
    valid_only: bool = True,
) -> list[dict]:
    """Back-compat wrapper: returns llm_endpoint resources."""
    return list_resources(
        jwt_token,
        categories=["llm_endpoint"],
        organization_id=organization_id,
        project_id=project_id,
        omit_not_ai=True,
        valid_only=valid_only,
    )


def list_models_and_assets(
    jwt_token: str,
    organization_id: str | None = None,
    project_id: str | None = None,
    categories: List[str] | None = None,  # e.g. ["model","model_assets"]
    omit_not_ai: bool = True,
) -> list[dict]:
    """Back-compat wrapper: returns model + model_assets resources (or a custom subset)."""
    return list_resources(
        jwt_token,
        categories=categories or ["model", "model_assets"],
        organization_id=organization_id,
        project_id=project_id,
        omit_not_ai=omit_not_ai,
    )


def dedupe_resources(resources: list[dict]) -> list[dict]:
    """Deduplicate by resource_instance_id while keeping the first occurrence."""
    seen = set()
    out: list[dict] = []
    for r in resources:
        rid = r.get("resource_instance_id")
        if rid and rid not in seen:
            seen.add(rid)
            out.append(r)
    return out


def list_pentest_templates(jwt: str) -> List[Dict[str, Any]]:
    if not config.CUSTOMER_ID:
        raise ValueError("CUSTOMER_ID env var is required to list pentest templates")
    resp = make_api_request(
        f"/v2/llm-pentest/customer/{config.CUSTOMER_ID}/templates",
        token=jwt,
        method="GET",
        accept="application/json",
        content_type=None,
        timeout=30,
    )
    data = resp.json()
    return data.get("llm_pentest_scan_templates", [])


# ---- Models & Model Assets helpers ----

def is_pentestable_model_asset(res: dict) -> bool:
    """
    We scan 'model' and 'model_assets' but exclude Model Card Files.
    """
    rtd = (res.get("resource_type_display_name") or "").strip()
    return rtd != "Model Card File"


def model_scan_check_policies(
    jwt_token: str,
    *,
    resource_instance_id: str,
    project_id: str | None,
    policies_to_scan: List[str],
    description: str = "CI Model Scan",
) -> dict:
    """
    POST /v1/posture-management/customers/{CUSTOMER_ID}/model-scanning/check-policies
    Query params: resource_instance_id, project_id (optional)
    Body: { "policies_to_scan": [...], "description": "..." }
    Returns JSON payload from API.
    """
    endpoint = f"/v1/posture-management/customers/{config.CUSTOMER_ID}/model-scanning/check-policies"
    params: Dict[str, Any] = {"resource_instance_id": resource_instance_id}
    if project_id:
        params["project_id"] = project_id

    resp = make_api_request(
        endpoint,
        token=jwt_token,
        method="POST",
        data={"policies_to_scan": policies_to_scan, "description": description},
        params=params,
        accept="application/json",
        content_type="application/json",
        timeout=120,
    )
    return resp.json()


# ---------- v2 GraphQL: Model Scan Full ----------

def query_model_scan_execution_full(jwt_token: str, model_scan_execution_id: str) -> dict:
    """
    Fetch execution outcome, resource, per-policy results, and overall stats
    for a given model scan execution (GraphQL).
    """
    graphql_query = """
    query ModelScanExecutionResults($customerId: UUID!, $modelScanExecutionId: UUID!) {
      modelScanExecution(filter: {customerId: $customerId, modelScanExecutionId: $modelScanExecutionId}) {
        modelScanExecutionId
        status
        startedAt
        outcomeLevel
      }
      resourceInstanceForModelScanExecution(filter: { customerId: $customerId, modelScanExecutionId: $modelScanExecutionId }) {
        displayName
        resourceInstanceId
      }
      modelScanResultsPerPolicy(filter: { customerId: $customerId, modelScanExecutionId: $modelScanExecutionId }) {
        failedTestCases
        policyName
        passedTestCases
        severity
        failedTestCaseDetails {
          modelScanExecutionId
          modelVulnerability
          modelVulnerabilityDescription
          richDetails {
            attackFlowDiagramMermaidSpec
            backgroundInformation
            findingDescription
            impact
            remediation
            title
          }
        }
      }
      modelScanOverallResults(filter: { customerId: $customerId, modelScanExecutionId: $modelScanExecutionId }) {
        passedTestCases
        failedTestCases
        totalTestCases
      }
    }
    """.strip()
    data = run_graphql(
        jwt_token,
        graphql_query,
        {"customerId": config.CUSTOMER_ID, "modelScanExecutionId": model_scan_execution_id},
        version="v2",
        timeout=60,
    )
    return data or {}


# ---------- v2 GraphQL: PentestScanSummaries ----------

_PENTEST_SCAN_SUMMARIES_QUERY = """
query PentestScanSummariesModelScans($customerId: UUID!, $organizationId: UUID) {
  pentestScanSummaries(
    filter: {
      sortOrder: DESC
      customerId: $customerId
      executionTypes: MODEL_SCAN
      organizationId: $organizationId
    }
  ) {
    items {
      executionStatus
      executionType
      modelScanExecutionId
      modelScanExecutionStatus
      modelScanIsCompleted
      modelScanPolicies
      modelScanScope
      numOfIssues
      outcomeLevel
      resourceInstance {
        displayName
        resourceIdentifier
        resourceInstanceId
        resourceType
      }
      scanId
      startedAt
    }
  }
}
""".strip()


# ---------- v1 GraphQL: Model Scan Details ----------

def query_model_scan_details(jwt_token: str, model_scan_execution_id: str) -> dict:
    """
    /v1/graphql: modelScanDetails — returns startAt, resource, issues, etc.
    """
    query = """
    query ModelScanDetails($customerId: UUID!, $scanId: UUID!) {
      modelScanDetails(filter: { customerId: $customerId, scanId: $scanId }) {
        customerId
        executionStatus
        isCompleted
        issues {
          createdAt
          issueId
          modelConfigurationPolicyName
          modelVulnerabilities
          modelVulnerabilitiesDescriptions
          severity
          status
        }
        numOfIssues
        outcomeLevel
        passed
        policies
        resource {
          displayName
          registeredAt
          resourceInstanceId
          resourceType
        }
        scanId
        scanType
        startAt
        target
        scope
      }
    }""".strip()
    data = run_graphql(
        jwt_token,
        query,
        {"customerId": config.CUSTOMER_ID, "scanId": model_scan_execution_id},
        version="v1",
        timeout=45,
    )
    return (data.get("modelScanDetails") or {})


# ---------- Generic polling wrapper + model-scan ID polling ----------

T = TypeVar("T")

def _poll_until(
    fetch_func: Callable[[], Optional[T]],
    timeout_secs: float,
    interval_secs: float,
) -> Optional[T]:
    """Generic polling helper: repeatedly calls fetch_func until it returns a truthy value or times out."""
    deadline = _t.monotonic() + max(0.0, timeout_secs)
    while _t.monotonic() < deadline:
        try:
            result = fetch_func()
            if result:
                return result
        except Exception as e:
            # Swallow and keep polling; callers should handle logging/retries if desired.
            pass
        _t.sleep(max(0.0, interval_secs))
    return None


def _try_fetch_model_scan_id_once(
    jwt_token: str,
    *,
    resource_instance_id: str,
    min_started_at_iso: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Fetch the most recent MODEL_SCAN summary rows (DESC, org-scoped if available)
    and return the first that matches the given resource_instance_id.
    If min_started_at_iso is provided, only accept summaries whose startedAt is
    >= that ISO timestamp.
    """
    variables = {
        "customerId": config.CUSTOMER_ID,
        "organizationId": getattr(config, "ORGANIZATION_ID", None),
    }

    data = run_graphql(
        jwt_token,
        _PENTEST_SCAN_SUMMARIES_QUERY,
        variables,
        version="v2",
        timeout=60,
    )

    items = (((data or {}).get("pentestScanSummaries") or {}).get("items")) or []

    # Helper: robust ISO8601 parsing (handles trailing 'Z')
    def _to_dt(s: Optional[str]):
        if not s:
            return None
        s2 = s.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s2)
        except Exception:
            return None

    min_dt = _to_dt(min_started_at_iso) if min_started_at_iso else None

    for it in items:
        ri = (it.get("resourceInstance") or {})
        if ri.get("resourceInstanceId") != resource_instance_id:
            continue
        if min_dt:
            started = _to_dt(it.get("startedAt"))
            # If we can't parse startedAt, be conservative and skip
            if not started or started < min_dt:
                continue
        return it

    return None


def poll_model_scan_execution_id(
    jwt_token: str,
    *,
    resource_instance_id: str,
    poll_interval_secs: float = 6.0,
    timeout_secs: float = 180.0,
    min_started_at_iso: Optional[str] = None,
) -> Optional[str]:
    """
    Poll GraphQL summaries until we can resolve a modelScanExecutionId for the given resource_instance_id.
    """
    def _fetch() -> Optional[str]:
        row = _try_fetch_model_scan_id_once(
            jwt_token,
            resource_instance_id=resource_instance_id,
            min_started_at_iso=min_started_at_iso,
        )
        if row:
            msid = row.get("modelScanExecutionId")
            return msid or None
        return None

    return _poll_until(_fetch, timeout_secs=timeout_secs, interval_secs=poll_interval_secs)
