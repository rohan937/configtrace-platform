"""Provider discovery adapters (message 2 of N).

Generic discovery (``discovery.py``) is the DEFAULT and, for all four
pilot providers certified so far (Sentry, Snowflake, Okta, Entra), it is
SUFFICIENT on its own — every provider in this repository so far follows
the same naming conventions (``<PROVIDER>_TRACKED_FIELDS_BY_TYPE``,
``_create_<provider>_integration``, ``reconnect_credentials_<provider>``,
``record_type == "<provider>_x"`` or a named constant resolved through the
provider's own schema module, etc). No pilot provider currently requires
an adapter override — see
``test_provider_certification_adapters.py::TestNoPilotAdapterNeeded``.

This module exists so that a FUTURE provider using a genuinely different
pattern (e.g. dispatch through a shared registration helper, generated
metadata, a frontend indirection layer that generic regex parsing cannot
follow) has a typed, declaratively-registered place to plug in — instead
of scattering ``if provider_id == "whatever"`` conditionals through
``gates.py`` or ``discovery.py``.

An adapter may only ever AUGMENT or CONFIRM generic discovery, never
silently override it: ``resolve()`` explicitly distinguishes agreement,
augmentation (adapter finds a strict superset — e.g. resolves an alias
the generic regex can't follow), and contradiction (the two disagree in
a way that isn't a strict superset) — a contradiction is never resolved
by picking one side silently; the caller (a certification gate) is
expected to surface it as an explicit fail/warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# Each hook returns a frozenset of discovered symbol values (or bools for
# the reconnect hook), or None to mean "this adapter has no opinion for
# this dimension — defer entirely to generic discovery".
_SetHook = Callable[[], "frozenset[str] | None"]
_BoolHook = Callable[[], "bool | None"]


@dataclass(frozen=True)
class ProviderDiscoveryAdapter:
    """A typed, provider-specific discovery augmentation.

    Every field is optional — an adapter only needs to implement the
    hooks for the dimensions where generic discovery is genuinely
    insufficient for that one provider.
    """

    provider_id: str
    discover_record_types: _SetHook | None = None
    discover_classifier_record_types: _SetHook | None = None
    discover_tracked_record_types: _SetHook | None = None
    discover_finding_rule_ids: _SetHook | None = None
    discover_credential_fields: _SetHook | None = None
    discover_frontend_form_fields: _SetHook | None = None
    discover_reconnect_dispatch: _BoolHook | None = None
    discover_completeness_scopes: _SetHook | None = None
    note: str = ""


_ADAPTERS: dict[str, ProviderDiscoveryAdapter] = {}


def register_adapter(adapter: ProviderDiscoveryAdapter) -> None:
    _ADAPTERS[adapter.provider_id] = adapter


def get_adapter(provider_id: str) -> ProviderDiscoveryAdapter | None:
    return _ADAPTERS.get(provider_id)


def registered_adapter_provider_ids() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


class DiscoveryContradiction(Exception):
    """Raised only if calling code chooses to treat a contradiction as
    fatal; gates in this framework instead catch the returned note and
    surface it as an explicit fail/warning status (see
    ``gates.gate_adapter_consistency``)."""


@dataclass(frozen=True)
class ResolvedSet:
    """Result of reconciling generic discovery against an optional
    adapter hook for one set-valued dimension."""

    value: frozenset[str]
    agreement: bool
    augmented: bool
    contradiction_note: str | None = None


def resolve_set(generic_result: frozenset[str], adapter_hook: _SetHook | None) -> ResolvedSet:
    """Reconcile a generic discovery result against an optional adapter
    hook.

    * hook is ``None`` or returns ``None`` -> pure generic, agreement=True
    * hook result == generic result -> agreement=True (adapter confirms)
    * hook result is a strict superset of generic result -> augmentation;
      the union is used and augmented=True
    * anything else (hook result is missing symbols generic found, or has
      unrelated extra symbols that are not a superset) -> CONTRADICTION;
      the generic result is kept as the safe default and
      contradiction_note is set — callers must not silently ignore this.
    """
    if adapter_hook is None:
        return ResolvedSet(value=generic_result, agreement=True, augmented=False)
    adapter_result = adapter_hook()
    if adapter_result is None:
        return ResolvedSet(value=generic_result, agreement=True, augmented=False)
    if adapter_result == generic_result:
        return ResolvedSet(value=generic_result, agreement=True, augmented=False)
    if adapter_result >= generic_result and adapter_result != generic_result:
        added = adapter_result - generic_result
        return ResolvedSet(
            value=adapter_result,
            agreement=False,
            augmented=True,
            contradiction_note=f"adapter augmented generic discovery with: {sorted(added)}",
        )
    missing_from_adapter = generic_result - adapter_result
    extra_in_adapter = adapter_result - generic_result
    return ResolvedSet(
        value=generic_result,
        agreement=False,
        augmented=False,
        contradiction_note=(
            "CONTRADICTION: adapter/generic discovery disagree — "
            f"missing_from_adapter={sorted(missing_from_adapter)} extra_in_adapter={sorted(extra_in_adapter)}"
        ),
    )
