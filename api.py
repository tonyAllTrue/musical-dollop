import re
import threading
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import requests
import config

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

def query_execution(jwt_token: str, scan_execution_id: str, full: bool = True) -> dict | None:
    graphql_query = """
    query PentestExecution($customerId: UUID!, $execId: UUID!) {
      llmPentestScanExecution(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $execId }
      ) {
        outcomeLevel
        finishedAt
      }
    }"""
    variables = {"customerId": config.CUSTOMER_ID, "execId": scan_execution_id}
    resp = make_api_request(
        "/v2/graphql",
        token=jwt_token,
        method="POST",
        data={"query": graphql_query, "variables": variables},
        accept="application/json",
        content_type="application/json",
        timeout=30,
    )
    gql = resp.json()
    if "errors" in gql:
        raise RuntimeError(gql["errors"])
    return gql.get("data", {}).get("llmPentestScanExecution")

def query_pentest_execution_full(jwt_token: str, scan_execution_id: str) -> dict:
    """
    Fetches execution, resource, reports, and per-category results (passed/failed/inconclusive).
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
      llmPentestScanExecutionReports(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        reportUrl
        type
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
    variables = {"customerId": config.CUSTOMER_ID, "llmPentestScanExecutionId": scan_execution_id}
    resp = make_api_request(
        "/v2/graphql",
        token=jwt_token,
        method="POST",
        data={"query": graphql_query, "variables": variables},
        accept="application/json",
        content_type="application/json",
        timeout=60,
    )
    gql = resp.json()
    if "errors" in gql:
        raise RuntimeError(gql["errors"])
    return gql.get("data", {})

# ---------- v1 GraphQL: aiSpmGetPentestIssues ----------

def query_spm_pentest_issues(
    jwt_token: str,
    *,
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    resource_display_names: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,        # ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"]
    statuses: Optional[List[str]] = None,          # ["UNRESOLVED","REMEDIATED","DISMISSED","ARCHIVED","OVERDUE"]
    pentest_findings: Optional[List[str]] = None,  # policy/category names, e.g. ["Prompt Injection"]
) -> List[dict]:
    """
    Call /v1/graphql -> aiSpmGetPentestIssues(filter: PentestIssueFilter!)
    Returns the list of objects under data.aiSpmGetPentestIssues.pentestFindings (each is a dict).
    NOTE: PentestIssueFilter does NOT include llmPentestScanExecutionId; match exec IDs client-side.
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

    # Build filter
    # Schema: customerId: UUID!, organizationId, projectId, issueSeverities, technologyTypes,
    #         projectNames, issueStatus, displayName, pentestFindings, resourceDisplayNames
    filter_obj: Dict[str, Any] = {
        "customerId": config.CUSTOMER_ID,
    }
    if organization_id:
        filter_obj["organizationId"] = organization_id
    if project_id:
        filter_obj["projectId"] = project_id
    if statuses:
        filter_obj["issueStatus"] = statuses
    else:
        filter_obj["issueStatus"] = ["UNRESOLVED"]
    if severities:
        filter_obj["issueSeverities"] = severities
    if resource_display_names:
        filter_obj["resourceDisplayNames"] = resource_display_names
    if pentest_findings:
        filter_obj["pentestFindings"] = pentest_findings

    resp = make_api_request(
        "/v1/graphql",
        token=jwt_token,
        method="POST",
        data={"query": query, "variables": {"filter": filter_obj}},
        accept="application/json",
        content_type="application/json",
        timeout=45,
    )
    payload = resp.json()
    if "errors" in payload:
        raise RuntimeError(payload["errors"])
    data = payload.get("data", {}) or {}
    wrapper = data.get("aiSpmGetPentestIssues") or {}
    findings = wrapper.get("pentestFindings") or []
    return findings if isinstance(findings, list) else []

# ---------- Inventory helpers ----------

def list_llm_endpoints(
    jwt_token: str,
    organization_id: str | None = None,
    project_id: str | None = None,
    valid_only: bool = True,
) -> list[dict]:
    """Server-side filter for llm_endpoints, optionally by organization or project."""
    params: Dict[str, Any] = {
        "resource_category": ["llm_endpoint"],
        "omit_not_ai": True,
    }
    if organization_id:
        params["organization"] = organization_id
    if project_id:
        params["project"] = project_id
    if valid_only:
        params["has_valid_pentest_connection_details"] = True

    endpoint = f"/v1/inventory/customer/{config.CUSTOMER_ID}/resources"
    resp = make_api_request(endpoint, token=jwt_token, method="GET", params=params)
    return resp.json().get("resources", [])

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

def find_template_id_by_name(jwt: str, name: str) -> str | None:
    for t in list_pentest_templates(jwt):
        if t.get("name") == name:
            return t.get("llm_pentest_scan_template_id")
    return None
