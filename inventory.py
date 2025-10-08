# Generic org/project/resource selector helper.
# Parameterized by list/dedupe functions and simple getter/predicate hooks.

from __future__ import annotations
from typing import Callable, Dict, List, Optional, Tuple
import config

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
      - ORGANIZATION_ID, PROJECT_IDS, TARGET_RESOURCE_IDS, TARGET_RESOURCE_NAMES
    Applies:
      - include_predicate (domain-specific inclusion filter)
      - valid_predicate (optional gating when HAS_VALID_PENTEST_CONNECTION_DETAILS=true)
    Returns:
      - selected_ids, {id -> name}
    """
    scope = config.INVENTORY_SCOPE
    print(f"\n[inv] Inventory selection scope: {scope}")

    # ---------------- Fetch ----------------
    found: List[dict] = []
    if scope == "organization":
        print(f"[inv] Fetching {entity_label} for organization scope…")
        kwargs = dict(jwt_token=jwt, organization_id=config.ORGANIZATION_ID or None, project_id=None)
        if pass_valid_only_to_api:
            kwargs["valid_only"] = config.HAS_VALID_PENTEST_CONNECTION_DETAILS
        found = list_fn(**kwargs)

    elif scope == "project":
        if not config.PROJECT_IDS:
            print("❌ INVENTORY_SCOPE=project but PROJECT_IDS is empty.")
            return [], {}
        print(f"[inv] Fetching {entity_label} for projects: {config.PROJECT_IDS}")
        batch: List[dict] = []
        for pid in config.PROJECT_IDS:
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
        if not by_id and not by_name:
            print("❌ INVENTORY_SCOPE=resource but no TARGET_RESOURCE_IDS or TARGET_RESOURCE_NAMES provided.")
            return [], {}

        filtered: List[dict] = []
        for r in candidates:
            rid = (id_getter(r) or "").lower()
            rname = name_getter(r) or ""
            if (by_id and rid in by_id) or (by_name and _name_match(rname, by_name)):
                filtered.append(r)

        print(f"[inv] Resource scope: matched {len(filtered)} of {len(candidates)} candidates")
        found = dedupe_fn(filtered) if dedupe_fn else filtered

    else:
        print(f"❌ Unknown INVENTORY_SCOPE='{scope}'. Use organization|project|resource.")
        return [], {}

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
