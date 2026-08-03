"""Discovery helpers for the Provider Certification Framework.

Every function here is READ-ONLY and STATIC:
  * imports real backend modules and introspects their module-level
    symbols (dicts, tuples, functions, classes) — no instantiation of
    connectors, no network calls, no DB session use;
  * or reads real source/text files from disk (frontend TypeScript,
    ``requirements.txt``) and parses them with regex/string search —
    never ``eval``/``exec``.

Nothing here ever touches a customer credential, an encrypted
integration row, or a live provider API. See
``test_provider_certification_discovery.py`` and
``test_provider_certification_runner.py`` for the tests that pin this.
"""

from __future__ import annotations

import re
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent
_FRONTEND_ROOT = _REPO_ROOT / "frontend"


def frontend_root() -> Path | None:
    return _FRONTEND_ROOT if _FRONTEND_ROOT.is_dir() else None


# ── Backend provider inventory ────────────────────────────────────────────────


def discover_backend_sync_provider_ids() -> frozenset[str]:
    """Providers dispatchable by app.services.sync_service."""
    from app.services import sync_service

    text = Path(sync_service.__file__).read_text()
    start = text.index("_SUPPORTED_PROVIDERS = (")
    end = text.index(")", start)
    block = text[start:end]
    return frozenset(re.findall(r'"([a-z_0-9]+)"', block))


def discover_backend_credential_schema_provider_literal(provider_id: str) -> bool:
    """True if provider_id appears as a Literal-style value in
    IntegrationCreateRequest.provider (schemas/integration.py)."""
    from app.schemas.integration import IntegrationCreateRequest

    try:
        req = IntegrationCreateRequest.model_fields["provider"]
    except KeyError:
        return False
    # Pydantic v2 stores the Literal annotation on the field; simplest
    # robust check is a source-text scan for the exact quoted value inside
    # the `provider:` Literal block.
    text = Path(_BACKEND_ROOT / "app" / "schemas" / "integration.py").read_text()
    start = text.index("class IntegrationCreateRequest")
    block = text[start : start + 4000]
    return f'"{provider_id}"' in block


def discover_worker_dispatch(provider_id: str) -> bool:
    from app.workers import sync_task

    text = Path(sync_task.__file__).read_text()
    return f'integration.provider == "{provider_id}"' in text


def discover_reconnect_router_dispatch(provider_id: str) -> bool:
    from app.routers import integrations as integrations_router

    text = Path(integrations_router.__file__).read_text()
    return f'integration.provider == "{provider_id}"' in text


def discover_reconnect_function_exists(provider_id: str) -> bool:
    from app.services import integration_service

    return hasattr(integration_service, f"reconnect_credentials_{provider_id}")


def discover_create_dispatch_function_exists(provider_id: str) -> bool:
    from app.services import integration_service

    return hasattr(integration_service, f"_create_{provider_id}_integration")


def discover_credential_schema_fields(provider_id: str) -> frozenset[str]:
    """Credential fields (``<provider>_*``) declared on IntegrationCreateRequest."""
    from app.schemas.integration import IntegrationCreateRequest

    prefix = f"{provider_id}_"
    return frozenset(f for f in IntegrationCreateRequest.model_fields if f.startswith(prefix))


def discover_reconnect_schema_fields(provider_id: str) -> frozenset[str]:
    from app.schemas.integration import IntegrationReconnectRequest

    prefix = f"{provider_id}_"
    return frozenset(f for f in IntegrationReconnectRequest.model_fields if f.startswith(prefix))


# ── Capability matrix ──────────────────────────────────────────────────────────


def discover_capability_entry(provider_id: str):
    """Return the ProviderCapability entry, or None if absent from the
    canonical (launched) list."""
    from app.services.provider_capability_matrix_service import get_provider_capability

    return get_provider_capability(provider_id)


def discover_capability_matrix_membership(provider_id: str) -> tuple[bool, bool]:
    """Return (in_complete_list, in_partial_staging_list)."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES,
        PROVIDER_CAPABILITIES_PARTIAL,
    )

    in_complete = provider_id in {p.provider for p in PROVIDER_CAPABILITIES}
    in_partial = provider_id in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    return in_complete, in_partial


# ── Security Finding registry / confidence / pack / coverage ─────────────────


def discover_registry_rule_ids(provider_id: str) -> frozenset[str]:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS

    prefix = f"{provider_id}_"
    return frozenset(k for k in KNOWN_RULE_KEYS if k.startswith(prefix))


def discover_confidence_rule_ids(provider_id: str) -> frozenset[str]:
    from app.services.security_rule_confidence import RULE_CONFIDENCE

    prefix = f"{provider_id}_"
    return frozenset(k for k in RULE_CONFIDENCE if k.startswith(prefix))


def discover_pack_rule_ids(provider_id: str) -> frozenset[str]:
    from app.services.security_rule_pack import _RULE_META

    prefix = f"{provider_id}_"
    return frozenset(k for k in _RULE_META if k.startswith(prefix))


def discover_coverage_rule_ids(provider_id: str) -> frozenset[str]:
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    prefix = f"{provider_id}_"
    return frozenset(k for k in RULE_RECORD_TYPES if k.startswith(prefix))


def discover_coverage_provider_membership(provider_id: str) -> bool:
    from app.services.security_coverage_service import PROVIDERS

    return provider_id in PROVIDERS


def discover_evaluator_registered(provider_id: str) -> bool:
    """True if the provider has an entry in
    security_finding_evaluator._PROVIDER_RULES."""
    from app.services import security_finding_evaluator

    return provider_id in security_finding_evaluator._PROVIDER_RULES


def discover_frontend_catalog_rule_ids(provider_id: str) -> frozenset[str] | None:
    """Rule keys present in the frontend securityRuleCatalog.ts for this
    provider. Returns None if the frontend tree is not mounted."""
    root = frontend_root()
    if root is None:
        return None
    path = root / "src" / "lib" / "securityRuleCatalog.ts"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    prefix = f"{provider_id}_"
    keys = re.findall(r'key:\s*"([a-z0-9_]+)"', text)
    return frozenset(k for k in keys if k.startswith(prefix))


# ── Connector / record inventory ──────────────────────────────────────────────


def discover_connector_class(provider_id: str, class_name: str):
    """Import and return the connector class object, or None."""
    try:
        module = __import__(f"app.connectors.{provider_id}", fromlist=[class_name])
    except ImportError:
        return None
    return getattr(module, class_name, None)


def discover_schema_record_type_constants(provider_id: str) -> frozenset[str]:
    """Every genuine record-type identity constant defined in
    app.connectors.<provider>_schema — i.e. a module-level constant whose
    NAME is exactly the uppercased form of its own string VALUE, such as
    ``SENTRY_ORGANIZATION = "sentry_organization"``.

    This deliberately excludes category/status/action constants that
    also happen to hold a ``"<provider>_..."``-prefixed string (e.g.
    ``ACTION_CATEGORY_SENTRY_APP = "sentry_app"``) — those are not
    record-type identities, and a looser "starts with the provider
    prefix" heuristic would wrongly count them as record types.
    """
    try:
        module = __import__(f"app.connectors.{provider_id}_schema", fromlist=["*"])
    except ImportError:
        return frozenset()
    prefix = f"{provider_id}_"
    found: set[str] = set()
    for name in dir(module):
        if name.startswith("_") or not name.isupper():
            continue
        value = getattr(module, name)
        if isinstance(value, str) and value.startswith(prefix) and name == value.upper():
            found.add(value)
    return frozenset(found)


def discover_diff_tracked_fields_dict(provider_id: str) -> dict[str, tuple[str, ...]] | None:
    """Return the ``_<PROVIDER>_TRACKED_FIELDS_BY_TYPE`` dict from
    diff_service.py, or None if the provider has no such dict (i.e. it
    falls back to generic/no tracked fields)."""
    from app.services import diff_service

    attr_name = f"_{provider_id.upper()}_TRACKED_FIELDS_BY_TYPE"
    return getattr(diff_service, attr_name, None)


def discover_classifier_dispatch_exists(provider_id: str) -> bool:
    """True if risk_service.classify_change() dispatches this provider's
    record-type prefix to a dedicated classify_<provider>_change()."""
    from app.services import risk_service

    text = Path(risk_service.__file__).read_text()
    return f'record_type.startswith("{provider_id}_")' in text and f"classify_{provider_id}_change" in text


def discover_classifier_record_type_dispatch(provider_id: str) -> frozenset[str]:
    """Record-type literals explicitly handled inside
    risk_rules/<provider>.py's classify_<provider>_change.

    Handles both dispatch styles used across providers:
      * raw string literals — ``record_type == "sentry_organization"``
      * named constants imported from ``<provider>_schema`` —
        ``record_type == SNOWFLAKE_ACCOUNT`` (resolved back to its
        string value via the schema module).
    """
    try:
        module = __import__(f"app.services.risk_rules.{provider_id}", fromlist=["*"])
    except ImportError:
        return frozenset()
    text = Path(module.__file__).read_text()

    literal_matches = set(re.findall(rf'record_type ==\s*"({provider_id}_[a-z0-9_]+)"', text))

    constant_names = set(re.findall(r"record_type ==\s*([A-Z][A-Z0-9_]*)", text))
    resolved: set[str] = set()
    if constant_names:
        try:
            schema_module = __import__(f"app.connectors.{provider_id}_schema", fromlist=["*"])
        except ImportError:
            schema_module = None
        if schema_module is not None:
            for name in constant_names:
                value = getattr(schema_module, name, None)
                if isinstance(value, str) and value.startswith(f"{provider_id}_"):
                    resolved.add(value)

    return frozenset(literal_matches | resolved)


def discover_removal_suppression_exists(provider_id: str) -> bool:
    from app.services import diff_service

    return hasattr(diff_service, f"_{provider_id}_removal_suppressed") and callable(
        getattr(diff_service, f"_{provider_id}_removal_suppressed")
    )


# ── Frontend provider parity ──────────────────────────────────────────────────


def _providers_ts_text() -> str | None:
    root = frontend_root()
    if root is None:
        return None
    path = root / "src" / "lib" / "providers.ts"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def discover_frontend_provider_ids() -> frozenset[str] | None:
    text = _providers_ts_text()
    if text is None:
        return None
    start = text.index("export const PROVIDER_IDS")
    end = text.index("];", start)
    return frozenset(re.findall(r'"([a-z_0-9]+)"', text[start:end]))


def discover_frontend_connectable_ids() -> frozenset[str] | None:
    text = _providers_ts_text()
    if text is None:
        return None
    start = text.index("export const CONNECTABLE_PROVIDER_IDS")
    end = text.index("];", start)
    return frozenset(re.findall(r'"([a-z_0-9]+)"', text[start:end]))


def discover_frontend_form_file_exists(form_filename: str) -> bool:
    root = frontend_root()
    if root is None:
        return False
    path = root / "src" / "components" / "integrations" / form_filename
    return path.is_file()


def discover_frontend_form_uses_password_input(form_filename: str) -> bool:
    root = frontend_root()
    if root is None:
        return False
    path = root / "src" / "components" / "integrations" / form_filename
    if not path.is_file():
        return False
    return 'type="password"' in path.read_text(encoding="utf-8")


def discover_frontend_form_wired_into_dispatcher(provider_id: str) -> bool:
    root = frontend_root()
    if root is None:
        return False
    path = root / "src" / "app" / "(app)" / "integrations" / "page.tsx"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return f'selectedProvider === "{provider_id}"' in text


# ── Provider-expansion freeze (global gate) ───────────────────────────────────


def discover_recommended_next_providers() -> frozenset[str]:
    from app.services.provider_expansion_framework import RECOMMENDED_NEXT_PROVIDERS

    return frozenset(p.provider for p in RECOMMENDED_NEXT_PROVIDERS)


def discover_frontend_future_provider_queue() -> frozenset[str] | None:
    root = frontend_root()
    if root is None:
        return None
    path = root / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    match = re.search(r"const NEXT_PROVIDERS_BRIEF[^=]*=\s*\[(.*?)\];", text, re.DOTALL)
    if not match:
        return None
    block = match.group(1)
    return frozenset(re.findall(r'label:\s*"([^"]+)"', block))


def discover_planned_next_stage_text() -> str:
    from app.services.provider_expansion_framework import get_framework

    return get_framework()["summary"]["planned_next_stage"]


# ── Dependency / env-var audit ─────────────────────────────────────────────────


def discover_requirements_text() -> str:
    path = _BACKEND_ROOT / "requirements.txt"
    return path.read_text() if path.is_file() else ""


def discover_prohibited_dependency_present(dependency_name: str) -> bool:
    text = discover_requirements_text().lower()
    return dependency_name.lower() in text


def discover_connector_source_text(provider_id: str) -> str | None:
    try:
        module = __import__(f"app.connectors.{provider_id}", fromlist=["*"])
    except ImportError:
        return None
    return Path(module.__file__).read_text()


def discover_global_env_var_reference(provider_id: str, env_var: str) -> bool:
    """True if the connector source text references a global os.environ
    lookup for this env var name (a red flag — customer credentials must
    come only from encrypted integration storage, never a global env
    var)."""
    text = discover_connector_source_text(provider_id)
    if text is None:
        return False
    return f'os.environ.get("{env_var}"' in text or f'os.getenv("{env_var}"' in text
