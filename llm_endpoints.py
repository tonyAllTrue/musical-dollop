# Wrapper around inventory.select_with_scope for LLM endpoints.

from __future__ import annotations
from typing import Dict, List, Tuple
import api
from inventory import select_with_scope


def select_llm_endpoints(jwt: str) -> Tuple[List[str], Dict[str, str]]:
    return select_with_scope(
        jwt=jwt,
        entity_label="LLM endpoints",
        list_fn=api.list_llm_endpoints,                         
        dedupe_fn=api.dedupe_resources,
        valid_predicate=lambda r: r.get("has_valid_pentest_connection_details", False),
        pass_valid_only_to_api=True,                             
    )


