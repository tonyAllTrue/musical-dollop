# Generic org/project/resource selector helper.
# Parameterized by list/dedupe functions and simple getter/predicate hooks.

from __future__ import annotations
from typing import Callable, Dict, List, Optional, Tuple
import sys
import config
import api

ListFn = Callable[..., List[dict]]
DedupeFn = Callable[[List[dict]], List[dict]]
Predicate = Callable[[dict], bool]
Getter = Callable[[dict], str]


def _default_id_getter(r: dict) -> str:
    return r.get("resource_instance_id") or ""


def _default_name_getter(r: dict) -> str:
    return (
        r.get("resource_display_name")
        or r.get("resource_type_display_name")
        or r.get("resource_type")
        or "<unnamed>"
    )


def _name_match(display: str, needles: List[str]) -> bool:
    dl = (display or "").lower()
    return any(substr in dl for substr in needles)


def resolve_config_org_and_projects(jwt: str) -> Tuple[Optional[str], List[str]]:
    """
    Resolve organization and project names/IDs from config to actual IDs.
    Returns (resolved_org_id, resolved_project_ids).
    
    Logic:
    1. If ORGANIZATION_NAME is set, resolve it to ID (overrides ORGANIZATION_ID)
    2. If PROJECT_NAMES is set, resolve them to IDs (merged with PROJECT_IDS)
    3. Otherwise, use ORGANIZATION_ID and PROJECT_IDS as-is
    """
    resolved_org_id: Optional[str] = None
    resolved_project_ids: List[str] = []
    
    # Resolve organization
    if config.ORGANIZATION_NAME:
        print(f"[config-resolve] Resolving organization name '{config.ORGANIZATION_NAME}'...")
        try:
            resolved_org_id = api.resolve_organization_name_to_id(jwt, config.ORGANIZATION_NAME)
            if resolved_org_id:
                print(f"[config-resolve] ✓ Resolved organization '{config.ORGANIZATION_NAME}' → {resolved_org_id}")
            else:
                print(f"[config-resolve] ✗ Could not resolve organization name '{config.ORGANIZATION_NAME}'")
        except Exception as e:
            print(f"[config-resolve] ✗ Error resolving organization name '{config.ORGANIZATION_NAME}': {e}")
            # Check if it's a permission error
            if "403" in str(e) or "permission" in str(e).lower():
                print(f"[config-resolve] ⚠️  Permission denied accessing organization lookup endpoint")
                print(f"[config-resolve] ⚠️  Falling back to ORGANIZATION_ID if set, or will fail validation")
    elif config.ORGANIZATION_ID:
        resolved_org_id = config.ORGANIZATION_ID
        print(f"[config-resolve] Using ORGANIZATION_ID: {resolved_org_id}")
    
    # Resolve projects
    if config.PROJECT_NAMES:
        print(f"[config-resolve] Resolving project names: {config.PROJECT_NAMES}...")
        try:
            resolved_from_names = api.resolve_project_names_or_ids(jwt, config.PROJECT_NAMES, resolved_org_id)
            resolved_project_ids.extend(resolved_from_names)
        except Exception as e:
            print(f"[config-resolve] ✗ Error resolving project names: {e}")
            if "403" in str(e) or "permission" in str(e).lower():
                print(f"[config-resolve] ⚠️  Permission denied accessing project lookup endpoint")
                print(f"[config-resolve] ⚠️  Falling back to PROJECT_IDS if set, or will fail validation")
    
    # Add any direct PROJECT_IDS
    if config.PROJECT_IDS:
        print(f"[config-resolve] Adding PROJECT_IDS: {config.PROJECT_IDS}")
        # Resolve these too in case they're actually names
        try:
            resolved_from_ids = api.resolve_project_names_or_ids(jwt, config.PROJECT_IDS, resolved_org_id)
            resolved_project_ids.extend(resolved_from_ids)
        except Exception as e:
            print(f"[config-resolve] ⚠️  Error validating PROJECT_IDS: {e}")
            # If resolution fails, assume they're valid UUIDs and add them anyway
            resolved_project_ids.extend(config.PROJECT_IDS)
    
    # Deduplicate project IDs
    resolved_project_ids = list(dict.fromkeys(resolved_project_ids))
    
    if resolved_project_ids:
        print(f"[config-resolve] Final resolved project IDs: {resolved_project_ids}")
    
    return resolved_org_id, resolved_project_ids


def validate_scope_requirements(
    scope: str,
    resolved_org_id: Optional[str],
    resolved_project_ids: List[str],
) -> None:
    """
    Validate that required scope identifiers are present before proceeding.
    Fails fast with clear error messages if requirements aren't met.
    
    Requirements:
    - organization scope: requires organization_id
    - project scope: requires at least one project_id
    - resource scope: requires organization_id OR at least one project_id (for access control)
    
    Raises SystemExit if validation fails.
    """
    print(f"\n[scope-validation] Validating scope requirements for '{scope}' scope...")
    
    if scope == "organization":
        if not resolved_org_id:
            print("=" * 80)
            print("✖ CONFIGURATION ERROR: Missing Organization Identifier")
            print("=" * 80)
            print("INVENTORY_SCOPE is set to 'organization' but no organization identifier provided.")
            print()
            print("Required: Set ONE of the following:")
            print("  - ORGANIZATION_ID (UUID)")
            print("  - ORGANIZATION_NAME (will be resolved to UUID)")
            print()
            print("Example configurations:")
            print("  .env file:")
            print("    ORGANIZATION_NAME=ACME Corporation")
            print("  OR")
            print("    ORGANIZATION_ID=364fe49b-6ea1-4a53-83db-f8311a9c8412")
            print()
            print("  GitHub Action:")
            print("    alltrue-organization-name: 'ACME Corporation'")
            print("  OR")
            print("    alltrue-organization-id: '364fe49b-6ea1-4a53-83db-f8311a9c8412'")
            print("=" * 80)
            sys.exit(1)
        print(f"[scope-validation] ✓ Organization scope validated: {resolved_org_id}")
    
    elif scope == "project":
        if not resolved_project_ids:
            print("=" * 80)
            print("✖ CONFIGURATION ERROR: Missing Project Identifier(s)")
            print("=" * 80)
            print("INVENTORY_SCOPE is set to 'project' but no project identifiers provided.")
            print()
            print("Required: Set ONE of the following:")
            print("  - PROJECT_IDS (comma-separated UUIDs)")
            print("  - PROJECT_NAMES (comma-separated names, will be resolved to UUIDs)")
            print()
            print("Example configurations:")
            print("  .env file:")
            print("    PROJECT_NAMES=Production,Staging,Development")
            print("  OR")
            print("    PROJECT_IDS=5c221ef3-86a5-49e0-bce9-df09b9a1d51a,7d332fg4-97b6-50f1-cde0-eg10c0b2e2m2")
            print()
            print("  GitHub Action:")
            print("    project-names: 'Production,Staging,Development'")
            print("  OR")
            print("    project-ids: '5c221ef3-86a5-49e0-bce9-df09b9a1d51a,7d332fg4-97b6-50f1-cde0-eg10c0b2e2m2'")
            print("=" * 80)
            sys.exit(1)
        print(f"[scope-validation] ✓ Project scope validated: {len(resolved_project_ids)} project(s)")
    
    elif scope == "resource":
        if not resolved_org_id and not resolved_project_ids:
            print("=" * 80)
            print("✖ CONFIGURATION ERROR: Missing Scope Context for Resource Selection")
            print("=" * 80)
            print("INVENTORY_SCOPE is set to 'resource' but no organization or project context provided.")
            print()
            print("⚠️  SECURITY REQUIREMENT: Resource-scoped scanning requires access control context")
            print("   to prevent unintended customer-wide scanning.")
            print()
            print("Required: Set AT LEAST ONE of the following:")
            print("  - ORGANIZATION_ID / ORGANIZATION_NAME")
            print("  - PROJECT_IDS / PROJECT_NAMES")
            print()
            print("Additionally required:")
            print("  - TARGET_RESOURCE_IDS (comma-separated UUIDs)")
            print("    OR")
            print("  - TARGET_RESOURCE_NAMES (comma-separated names)")
            print()
            print("Example configurations:")
            print("  .env file:")
            print("    INVENTORY_SCOPE=resource")
            print("    ORGANIZATION_NAME=ACME Corporation")
            print("    TARGET_RESOURCE_NAMES=production-chatbot,staging-api")
            print()
            print("  GitHub Action:")
            print("    inventory-scope: 'resource'")
            print("    alltrue-organization-name: 'ACME Corporation'")
            print("    target-resource-names: 'production-chatbot,staging-api'")
            print("=" * 80)
            sys.exit(1)
        
        # Additional validation for resource scope: must have resource identifiers
        has_resource_ids = bool(config.TARGET_RESOURCE_IDS)
        has_resource_names = bool(config.TARGET_RESOURCE_NAMES)
        
        if not has_resource_ids and not has_resource_names:
            print("=" * 80)
            print("✖ CONFIGURATION ERROR: Missing Resource Identifiers")
            print("=" * 80)
            print("INVENTORY_SCOPE is set to 'resource' but no resource identifiers provided.")
            print()
            print("Required: Set AT LEAST ONE of the following:")
            print("  - TARGET_RESOURCE_IDS (comma-separated UUIDs)")
            print("  - TARGET_RESOURCE_NAMES (comma-separated names)")
            print()
            print("Example configurations:")
            print("  .env file:")
            print("    TARGET_RESOURCE_NAMES=production-chatbot,staging-api,ml-model-v2")
            print("  OR")
            print("    TARGET_RESOURCE_IDS=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
            print()
            print("  GitHub Action:")
            print("    target-resource-names: 'production-chatbot,staging-api'")
            print("  OR")
            print("    target-resource-ids: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'")
            print("=" * 80)
            sys.exit(1)
        
        context = []
        if resolved_org_id:
            context.append(f"organization {resolved_org_id}")
        if resolved_project_ids:
            context.append(f"{len(resolved_project_ids)} project(s)")
        print(f"[scope-validation] ✓ Resource scope validated with context: {', '.join(context)}")
    
    else:
        print("=" * 80)
        print(f"✖ CONFIGURATION ERROR: Invalid INVENTORY_SCOPE")
        print("=" * 80)
        print(f"INVENTORY_SCOPE is set to '{scope}' which is not a valid option.")
        print()
        print("Valid options:")
        print("  - organization : Scan all resources in an organization")
        print("  - project      : Scan all resources in specific project(s)")
        print("  - resource     : Scan specific named resources")
        print()
        print("Example:")
        print("  INVENTORY_SCOPE=organization")
        print("=" * 80)
        sys.exit(1)


def select_with_scope(
    *,
    jwt: str,
    entity_label: str,
    list_fn: ListFn,                                # expects kwargs: jwt_token, organization_id, project_id, (valid_only?) depending on API
    dedupe_fn: Optional[DedupeFn] = None,
    id_getter: Getter = _default_id_getter,
    name_getter: Getter = _default_name_getter,
    include_predicate: Optional[Predicate] = None,   # e.g., api.is_pentestable_model_asset
    valid_predicate: Optional[Predicate] = None,     # e.g., lambda r: r.get("has_valid_pentest_connection_details", False)
    pass_valid_only_to_api: bool = False,            # pass valid_only to list_fn when supported
) -> Tuple[List[str], Dict[str, str]]:
    """
    Generic org/project/resource selection based on config:
      - INVENTORY_SCOPE: organization|project|resource
      - ORGANIZATION_ID/NAME, PROJECT_IDS/NAMES, TARGET_RESOURCE_IDS, TARGET_RESOURCE_NAMES
    Applies:
      - include_predicate (domain-specific inclusion filter)
      - valid_predicate (optional gating when HAS_VALID_PENTEST_CONNECTION_DETAILS=true)
    Returns:
      - selected_ids, {id -> name}
    """
    # First, resolve any organization/project names to IDs
    resolved_org_id, resolved_project_ids = resolve_config_org_and_projects(jwt)
    
    # Validate scope requirements BEFORE proceeding
    scope = config.INVENTORY_SCOPE.lower()
    validate_scope_requirements(scope, resolved_org_id, resolved_project_ids)
    
    # Update config with resolved values for use by other components
    if resolved_org_id:
        config.ORGANIZATION_ID = resolved_org_id
    if resolved_project_ids:
        config.PROJECT_IDS = resolved_project_ids
    
    print(f"\n[inv] Inventory selection scope: {scope}")

    # ---------------- Fetch ----------------
    found: List[dict] = []
    if scope == "organization":
        print(f"[inv] Fetching {entity_label} for organization scope…")
        kwargs = dict(jwt_token=jwt, organization_id=resolved_org_id, project_id=None)
        if pass_valid_only_to_api:
            kwargs["valid_only"] = config.HAS_VALID_PENTEST_CONNECTION_DETAILS
        found = list_fn(**kwargs)

    elif scope == "project":
        print(f"[inv] Fetching {entity_label} for projects: {resolved_project_ids}")
        batch: List[dict] = []
        for pid in resolved_project_ids:
            kwargs = dict(jwt_token=jwt, organization_id=None, project_id=pid)
            if pass_valid_only_to_api:
                kwargs["valid_only"] = config.HAS_VALID_PENTEST_CONNECTION_DETAILS
            res = list_fn(**kwargs)
            print(f"    - Project {pid}: {len(res)} items")
            batch.extend(res)
        found = dedupe_fn(batch) if dedupe_fn else batch

    elif scope == "resource":
        print(f"[inv] Fetching {entity_label} for resource scope (will filter by IDs/names)…")
        kwargs = dict(jwt_token=jwt, organization_id=None, project_id=None)
        if pass_valid_only_to_api:
            kwargs["valid_only"] = config.HAS_VALID_PENTEST_CONNECTION_DETAILS
        candidates = list_fn(**kwargs)

        by_id = {r.lower() for r in config.TARGET_RESOURCE_IDS}
        by_name = [s.lower() for s in config.TARGET_RESOURCE_NAMES]

        filtered: List[dict] = []
        for r in candidates:
            rid = (id_getter(r) or "").lower()
            rname = name_getter(r) or ""
            if (by_id and rid in by_id) or (by_name and _name_match(rname, by_name)):
                filtered.append(r)

        print(f"[inv] Resource scope: matched {len(filtered)} of {len(candidates)} candidates")
        found = dedupe_fn(filtered) if dedupe_fn else filtered

    print(f"[+] Found {len(found)} {entity_label} (pre-filter)")

    # ---------------- Domain include-only filter (optional) ----------------
    if include_predicate:
        pre = len(found)
        found = [r for r in found if include_predicate(r)]
        print(f"[i] Included {len(found)}/{pre} after domain-specific filter")

    # ---------------- Valid gate (optional) ----------------
    chosen: List[dict]
    if valid_predicate:
        if config.HAS_VALID_PENTEST_CONNECTION_DETAILS:
            chosen = [r for r in found if valid_predicate(r)]
            print(f"[+] {len(chosen)} {entity_label} passed 'valid' predicate filter")
        else:
            chosen = found
            valid_ct = sum(1 for r in found if valid_predicate(r))
            print(f"[i] 'valid' filter disabled; of these, {valid_ct} would have passed")
    else:
        chosen = found

    # ---------------- Mapping ----------------
    mapping: Dict[str, str] = {}
    for r in chosen:
        rid = id_getter(r)
        name = name_getter(r)
        if rid:
            mapping[rid] = name
            print(f"    - {name}\n      ID: {rid}\n")

    selected_ids = list(mapping.keys())
    print(f"[+] Total selected {entity_label}: {len(selected_ids)}")
    return selected_ids, mapping
