import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

import auth
import api
import config

API_ROOT = "https://api.github.com"


def _gh_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {config.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }


def github_ready() -> bool:
    return bool(config.GITHUB_TOKEN and config.GITHUB_REPOSITORY)


def _post_issue(title: str, body: str, labels: List[str]) -> tuple[bool, str]:
    url = f"{API_ROOT}/repos/{config.GITHUB_REPOSITORY}/issues"
    payload: Dict[str, Any] = {"title": title, "body": body, "labels": labels}
    if config.GITHUB_ASSIGNEES:
        payload["assignees"] = config.GITHUB_ASSIGNEES
    r = requests.post(url, headers=_gh_headers(), json=payload, timeout=30)
    if r.status_code == 201:
        num = r.json().get("number")
        return True, f"Created issue #{num}: {title}"
    return False, f"Failed ({r.status_code}): {r.text}"


def _format_result_line(r: dict) -> str:
    rid = r.get("resource_id") or "?"
    name = r.get("resource_name") or "?"
    status = r.get("status") or "?"
    out = r.get("outcome") or "Unknown"
    jid = r.get("job_id") or "-"
    sid = r.get("scan_execution_id") or "-"
    return f"- **{name}** (id: `{rid}`) — status: `{status}`, outcome: **{out}**, job: `{jid}`, exec: `{sid}`"


def _make_title(prefix: str, severity: Optional[str], resource_name: str) -> str:
    sev = severity.capitalize() if severity else "Unknown"
    return f"[Pentest] {prefix}: {sev} — {resource_name}"

def _category_severity_meets_min(sev: str) -> bool:
    # sev is expected like "CRITICAL"/"HIGH"/...
    norm = config.normalize_category_severity(sev)
    if not norm:
        return False  # unknown => skip
    min_norm = config.CATEGORY_ISSUE_MIN_SEVERITY or "INFORMATIONAL"
    return config.CATEGORY_SEVERITY_INDEX[norm] <= config.CATEGORY_SEVERITY_INDEX[min_norm]


def create_issues_for_threshold_breaches(breaches: List[dict], threshold: str) -> int:
    """
    Create one issue per resource that breached threshold.
    """
    if not breaches:
        return 0
    if not github_ready():
        print("⚠️  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in breaches:
        outcome = (r.get("outcome") or "unknown").lower()
        title = _make_title("Outcome threshold breach", outcome, r.get("resource_name") or "?")
        body = (
            f"Outcome **{r.get('outcome','Unknown')}** breached configured threshold **{threshold.capitalize()}**.\n\n"
            f"**When:** {now}\n"
            f"**Customer:** `{config.CUSTOMER_ID}`\n"
            f"{_format_result_line(r)}\n"
        )
        labels = list({*config.GITHUB_DEFAULT_LABELS, "threshold-breach", outcome})
        ok, msg = _post_issue(title, body, labels)
        print(("📝 " if ok else "❌ ") + msg)
        if ok:
            created += 1
    return created


def create_issues_for_hard_failures(failures: List[dict]) -> int:
    """
    Create one issue per hard failure.
    """
    if not failures:
        return 0
    if not github_ready():
        print("⚠️  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in failures:
        title = _make_title("Start/Run failure", None, r.get("resource_name") or "?")
        body = (
            f"A pentest failed to start or errored.\n\n"
            f"**When:** {now}\n"
            f"**Customer:** `{config.CUSTOMER_ID}`\n"
            f"{_format_result_line(r)}\n"
            f"\n```\n{(r.get('error') or 'n/a')}\n```\n"
        )
        labels = list({*config.GITHUB_DEFAULT_LABELS, "hard-failure"})
        ok, msg = _post_issue(title, body, labels)
        print(("📝 " if ok else "❌ ") + msg)
        if ok:
            created += 1
    return created


# ---------------------------
# v1 GraphQL enrichment helpers
# ---------------------------

def _norm(s: Optional[str]) -> str:
    return " ".join((s or "").strip().split()).lower()


def _pick_best_issue_match(
    findings: List[dict],
    *,
    exec_id: Optional[str],
    res_name: str,
    cat_name: str,
) -> Optional[dict]:
    """
    From a list of pentest findings rows (platform issues), pick the best match:
      1) Prefer exact matching exec id if present
      2) Else match on (policyName == category) AND (resourceDisplayName == res_name), choose most recent
      3) Else None
    """
    if not findings:
        return None

    cat_norm = _norm(cat_name)
    res_norm = _norm(res_name)

    # 1) Prefer exact exec id match
    if exec_id:
        exact = [f for f in findings if _norm(f.get("llmPentestScanExecutionId")) == _norm(exec_id)]
        if exact:
            # If multiple, choose most recent by issueCreatedDate
            def _ts(row: dict) -> datetime:
                v = row.get("issueCreatedDate") or ""
                try:
                    return datetime.fromisoformat(v.replace("Z", "+00:00"))
                except Exception:
                    return datetime.min.replace(tzinfo=timezone.utc)
            return sorted(exact, key=_ts, reverse=True)[0]

    # 2) Category + resource match
    candidates = [
        f for f in findings
        if _norm(f.get("policyName")) == cat_norm and _norm(f.get("resourceDisplayName")) == res_norm
    ]
    if candidates:
        def _ts(row: dict) -> datetime:
            v = row.get("issueCreatedDate") or ""
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)
        return sorted(candidates, key=_ts, reverse=True)[0]

    return None


def _enrich_with_platform_issue_block(
    jwt: str,
    *,
    exec_id: Optional[str],
    res_name: str,
    cat_name: str,
) -> tuple[str, Optional[List[str]]]:
    """
    Query /v1/graphql aiSpmGetPentestIssues for a likely-matching platform issue.
    Returns (markdown_block, extra_labels or None). Returns ("", None) if nothing found or on error.
    """
    try:
        # Scope narrowly: by resource name + category name. Default status to UNRESOLVED inside API helper.
        findings = api.query_spm_pentest_issues(
            jwt_token=jwt,
            organization_id=getattr(config, "ORGANIZATION_ID", None),
            project_id=(config.PROJECT_IDS[0] if getattr(config, "PROJECT_IDS", []) else None),
            resource_display_names=[res_name],
            pentest_findings=[cat_name],
            severities=None,
            statuses=None,  # default to UNRESOLVED in helper
        )
    except Exception as e:
        print(f"[enrich:gql] Skipping enrichment for {cat_name}: {e}")
        return "", None

    match = _pick_best_issue_match(findings, exec_id=exec_id, res_name=res_name, cat_name=cat_name)
    if not match:
        return "", None

    proj_list = match.get("projectNames") or []
    proj_line = f"- Project(s): {', '.join(proj_list)}\n" if proj_list else ""
    block = (
        "\n\n**Platform Issue (AllTrue)**\n"
        f"- Issue ID: `{match.get('issueId') or '?'}`\n"
        f"- Status: {match.get('status') or 'UNKNOWN'}\n"
        f"- Severity: {match.get('severity') or 'UNKNOWN'}\n"
        f"- First Discovered At: {match.get('issueCreatedDate') or '?'}\n"
        f"- Policy (category): {match.get('policyName') or cat_name}\n"
        f"- Resource: {match.get('resourceDisplayName') or res_name}\n"
        f"{proj_line}"
    )
    return block, ["platform-issue-linked"]


# ---------------------------
# Per-category issue creation
# ---------------------------

def create_failed_category_issues_for_results(results: List[dict]) -> int:
    """
    For each result with a scan_execution_id, fetch per-category details via v2 GraphQL
    and create one GitHub issue per failed category (categoryDisplayName + severity).
    Enrich each issue body by querying /v1/graphql aiSpmGetPentestIssues (PentestIssueFilter).
    """
    if not github_ready():
        print("⚠️  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    if not results:
        return 0

    jwt = auth.get_jwt_token(config.API_KEY)
    created_total = 0

    for r in results:
        exec_id = r.get("scan_execution_id")
        if not exec_id:
            continue

        try:
            data = api.query_pentest_execution_full(jwt, exec_id)
        except Exception as e:
            print(f"❌ GraphQL fetch failed for exec {exec_id}: {e}")
            continue

        exec_info = data.get("llmPentestScanExecution") or {}
        resource = data.get("resourceInstanceForLlmPentestScanExecution") or {}
        failed_per = data.get("failedCategoriesResultsPerCategory") or []

        if not failed_per:
            continue

        res_name = resource.get("displayName") or r.get("resource_name") or "Unknown resource"
        res_id = resource.get("resourceInstanceId") or r.get("resource_id") or "?"
        model = exec_info.get("chosenLlmModel") or "?"
        started = exec_info.get("startedAt") or "?"
        outcome = exec_info.get("outcomeLevel") or r.get("outcome") or "Unknown"

        for cat in failed_per:
            severity = (cat.get("severity") or "UNKNOWN").upper()
            if not _category_severity_meets_min(severity):
                # Skip creating an issue for severities below the configured minimum
                continue
            cat_name = cat.get("categoryDisplayName") or "Unnamed Category"
            case_total = cat.get("totalTestCases") or 0
            failed = cat.get("failedTestCases") or 0
            passed = cat.get("passedTestCases") or 0

            # Title: one per (execution × category)
            title = f"[Pentest][{severity}] {cat_name} — {res_name}"

            # Include a trimmed list of failed details (to keep issues readable)
            details = cat.get("failedTestCaseDetails") or []
            detail_lines: List[str] = []
            for i, d in enumerate(details[:5], start=1):  # cap to 5 examples
                prompt = (d.get("externalPrompt") or "").strip()
                reason = (d.get("failedReason") or "").strip()
                output = (d.get("output") or "").strip()
                # light trimming to avoid gigantic issues
                prompt_short = textwrap.shorten(prompt.replace("\n", " ").strip(), width=300, placeholder="…")
                output_short = textwrap.shorten(output.replace("\n", " ").strip(), width=300, placeholder="…")
                reason_short = textwrap.shorten(reason.replace("\n", " ").strip(), width=500, placeholder="…")
                detail_lines.append(
                    f"**Example {i}**\n"
                    f"- Failed Reason: {reason_short}\n"
                    f"- Prompt (trimmed): `{prompt_short}`\n"
                    f"- Output (trimmed): `{output_short}`\n"
                )

            # Collapsible examples section
            if details:
                shown = min(len(details), 5)
                examples_total = len(details)
                suffix = f" of {examples_total}" if examples_total > 5 else ""
                examples_md = (
                    "<details>\n"
                    f"<summary><strong>Failed Examples</strong> ({shown}{suffix})</summary>\n\n"
                    + "\n".join(detail_lines)
                    + (
                        f"\n\n_…and {examples_total - 5} more failed test case(s)_"
                        if examples_total > 5 else ""
                    )
                    + "\n</details>"
                )
            else:
                examples_md = "_No example details provided_"

            # Enrichment via v1 GraphQL (PentestIssueFilter), best-effort
            enrich_block, extra_labels = _enrich_with_platform_issue_block(
                jwt,
                exec_id=exec_id,
                res_name=res_name,
                cat_name=cat_name,
            )

            # Unique marker to help future deduplication
            marker = f"<!-- llm_pentest_exec:{exec_id} category:{cat_name} -->"

            body = (
                f"{marker}\n"
                f"**Resource Name and ID:** {res_name} (`{res_id}`)\n"
                f"**Pentest Scan Execution ID:** `{exec_id}`\n"
                f"**Outcome:** **{outcome}**\n"
                f"**Model:** `{model}`  \n"
                f"**Started At:** {started}\n"
                f"\n"
                f"**Category:** {cat_name}\n"
                f"**Severity:** **{severity}**\n"
                f"**Results:** {failed} failed / {passed} passed / {case_total} total\n"
                f"\n"
                f"{examples_md}"
                + (enrich_block if enrich_block else "")
            )

            labels = list({*config.GITHUB_DEFAULT_LABELS, "pentest-category-failure", severity.lower()})
            if extra_labels:
                labels = list({*labels, *extra_labels})

            ok, msg = _post_issue(title, body, labels)
            print(("📝 " if ok else "❌ ") + msg)
            if ok:
                created_total += 1

    if created_total:
        print(f"📝 Created {created_total} per-category GitHub issue(s) via GraphQL.")
    return created_total