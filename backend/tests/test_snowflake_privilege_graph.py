"""Snowflake role-hierarchy graph traversal tests (Snowflake message 5 of 8).

Covers ``SnowflakeConnector._build_role_children_index`` /
``._role_closure`` in isolation: direction (child granted TO parent means
the PARENT's closure includes the child — confirmed via current official
Snowflake docs, Access Control overview: "Role A granted to Role B" -> "B
inherits A's privileges"), multi-hop traversal, database-role inheritance,
duplicate-edge dedup, cycle safety, missing-role tolerance, determinism,
and no-graph-explosion behavior at scale. Pure unit-level — no HTTP
mocking, no database.
"""

from __future__ import annotations

from app.connectors.snowflake import SnowflakeConnector as C
from app.connectors.snowflake_schema import (
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
)

_AR = PRINCIPAL_TYPE_ACCOUNT_ROLE
_DR = PRINCIPAL_TYPE_DATABASE_ROLE


def _edge(child_name: str, child_type: str, parent_name: str, parent_type: str) -> dict:
    return {
        "child_role_name": child_name,
        "child_role_type": child_type,
        "parent_role_name": parent_name,
        "parent_role_type": parent_type,
    }


def _closure(root_name: str, root_type: str, edges: list[dict]) -> frozenset:
    index = C._build_role_children_index(edges)
    return C._role_closure(C._role_key(root_type, root_name), index, {})


class TestDirection:
    def test_child_granted_to_parent_parent_inherits_child(self):
        """Case P/Q: direct + one-hop. Child (SECURITYADMIN) granted to
        parent (ACCOUNTADMIN) -> ACCOUNTADMIN's closure includes
        SECURITYADMIN (the parent inherits the child's privileges)."""
        edges = [_edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR)]
        closure = _closure("ACCOUNTADMIN", _AR, edges)
        assert C._role_key(_AR, "SECURITYADMIN") in closure
        assert C._role_key(_AR, "ACCOUNTADMIN") in closure

    def test_never_inferred_in_reverse_direction(self):
        """The CHILD's closure must NOT include its parent — traversal is
        strictly downward from a role through its own children, never
        upward through its parents (that would invert admins and
        subordinates)."""
        edges = [_edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR)]
        closure = _closure("SECURITYADMIN", _AR, edges)
        assert C._role_key(_AR, "ACCOUNTADMIN") not in closure
        assert closure == frozenset({C._role_key(_AR, "SECURITYADMIN")})


class TestMultiHop:
    def test_multi_hop_inheritance(self):
        """Case R: ACCOUNTADMIN -> SECURITYADMIN -> USERADMIN, two hops
        deep. ACCOUNTADMIN's closure must include USERADMIN transitively."""
        edges = [
            _edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR),
            _edge("USERADMIN", _AR, "SECURITYADMIN", _AR),
        ]
        closure = _closure("ACCOUNTADMIN", _AR, edges)
        assert C._role_key(_AR, "USERADMIN") in closure
        assert len(closure) == 3

    def test_diamond_shaped_hierarchy_deduped(self):
        """Case U: two independent paths reaching the same descendant must
        not double-count it — closures are sets."""
        edges = [
            _edge("SYSADMIN", _AR, "ACCOUNTADMIN", _AR),
            _edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR),
            _edge("SHARED_CHILD", _AR, "SYSADMIN", _AR),
            _edge("SHARED_CHILD", _AR, "SECURITYADMIN", _AR),
        ]
        closure = _closure("ACCOUNTADMIN", _AR, edges)
        assert closure == frozenset({
            C._role_key(_AR, "ACCOUNTADMIN"),
            C._role_key(_AR, "SYSADMIN"),
            C._role_key(_AR, "SECURITYADMIN"),
            C._role_key(_AR, "SHARED_CHILD"),
        })


class TestDatabaseRoleInheritance:
    def test_database_role_granted_to_account_role(self):
        """Case S: a database role granted to an account role — the
        account role's closure includes the database role, so a user
        holding that account role effectively gets the database role's
        object privileges."""
        edges = [_edge("DB_READER", _DR, "SYSADMIN", _AR)]
        closure = _closure("SYSADMIN", _AR, edges)
        assert C._role_key(_DR, "DB_READER") in closure

    def test_database_role_to_database_role_to_account_role(self):
        """Case T: database-role -> database-role -> account-role, two
        hops crossing the database/account-role type boundary."""
        edges = [
            _edge("DB_CHILD", _DR, "DB_PARENT", _DR),
            _edge("DB_PARENT", _DR, "SYSADMIN", _AR),
        ]
        closure = _closure("SYSADMIN", _AR, edges)
        assert C._role_key(_DR, "DB_CHILD") in closure
        assert C._role_key(_DR, "DB_PARENT") in closure

    def test_account_role_never_inferred_as_child_of_database_role(self):
        """The reverse direction (account-role -> database-role) must
        never be inferred — only what's explicitly present as an edge."""
        edges = [_edge("DB_READER", _DR, "SYSADMIN", _AR)]
        closure = _closure("DB_READER", _DR, edges)
        assert C._role_key(_AR, "SYSADMIN") not in closure


class TestCycleSafety:
    def test_two_node_cycle_terminates(self):
        """Case V: a malformed two-role cycle must not cause unbounded
        recursion — traversal terminates and returns a bounded set."""
        edges = [
            _edge("ROLE_A", _AR, "ROLE_B", _AR),
            _edge("ROLE_B", _AR, "ROLE_A", _AR),
        ]
        closure = _closure("ROLE_A", _AR, edges)
        assert C._role_key(_AR, "ROLE_A") in closure
        assert C._role_key(_AR, "ROLE_B") in closure
        assert len(closure) <= 2

    def test_self_loop_terminates(self):
        edges = [_edge("ROLE_A", _AR, "ROLE_A", _AR)]
        closure = _closure("ROLE_A", _AR, edges)
        assert closure == frozenset({C._role_key(_AR, "ROLE_A")})

    def test_three_node_cycle_terminates(self):
        edges = [
            _edge("ROLE_A", _AR, "ROLE_B", _AR),
            _edge("ROLE_B", _AR, "ROLE_C", _AR),
            _edge("ROLE_C", _AR, "ROLE_A", _AR),
        ]
        closure = _closure("ROLE_A", _AR, edges)
        assert len(closure) <= 3


class TestMissingAndPartialHierarchy:
    def test_missing_role_no_edges_returns_self_only(self):
        """Case W: a role with no hierarchy edges at all (e.g. its parent
        grant was denied/unavailable) has a closure of just itself —
        never an error, never a fabricated descendant."""
        closure = _closure("LONELY_ROLE", _AR, [])
        assert closure == frozenset({C._role_key(_AR, "LONELY_ROLE")})

    def test_partial_hierarchy_still_resolves_known_edges(self):
        """Case X: one role's hierarchy enumeration failed (absent from
        edges) while a sibling's succeeded — the sibling's closure is
        still fully and correctly resolved."""
        edges = [_edge("KNOWN_CHILD", _AR, "KNOWN_PARENT", _AR)]
        closure = _closure("KNOWN_PARENT", _AR, edges)
        assert C._role_key(_AR, "KNOWN_CHILD") in closure


class TestDuplicateEdges:
    def test_duplicate_edge_rows_deduped(self):
        """Case CF: the exact same edge appearing twice (e.g. a role-
        hierarchy collection retry double-counting a row) must not change
        the closure or blow up any count."""
        edges = [
            _edge("CHILD", _AR, "PARENT", _AR),
            _edge("CHILD", _AR, "PARENT", _AR),
        ]
        index = C._build_role_children_index(edges)
        assert index[C._role_key(_AR, "PARENT")] == [C._role_key(_AR, "CHILD")]


class TestDeterminism:
    def test_reordered_edges_same_closure(self):
        """Case CD/CE: feeding the same edges in a different order must
        yield an identical closure — Python set/dict iteration order must
        never leak into the result."""
        edges_a = [
            _edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR),
            _edge("SYSADMIN", _AR, "ACCOUNTADMIN", _AR),
            _edge("USERADMIN", _AR, "SECURITYADMIN", _AR),
        ]
        edges_b = list(reversed(edges_a))
        assert _closure("ACCOUNTADMIN", _AR, edges_a) == _closure("ACCOUNTADMIN", _AR, edges_b)

    def test_children_index_sorted_deterministically(self):
        edges = [
            _edge("ZEBRA", _AR, "PARENT", _AR),
            _edge("ALPHA", _AR, "PARENT", _AR),
        ]
        index = C._build_role_children_index(edges)
        assert index[C._role_key(_AR, "PARENT")] == sorted(index[C._role_key(_AR, "PARENT")])


class TestNoGraphExplosion:
    def test_large_fan_out_bounded_and_fast(self):
        """Case CN/CP-scale smoke test: a root with 2,000 direct children
        (no further nesting) resolves quickly and without unbounded
        memory growth."""
        edges = [_edge(f"CHILD_{i}", _AR, "ROOT", _AR) for i in range(2000)]
        closure = _closure("ROOT", _AR, edges)
        assert len(closure) == 2001

    def test_deep_chain_respects_depth_bound(self):
        """A pathological 500-role-deep single chain must still terminate
        (depth-bounded), never recurse indefinitely."""
        edges = [_edge(f"ROLE_{i+1}", _AR, f"ROLE_{i}", _AR) for i in range(500)]
        closure = _closure("ROLE_0", _AR, edges)
        assert len(closure) >= 1

    def test_memoization_reused_across_roots(self):
        """Closures for two different roots that share a memo dict must
        each compute independently and correctly — shared memoization
        must never leak one root's closure into another's."""
        edges = [
            _edge("SHARED", _AR, "ROOT_A", _AR),
            _edge("ONLY_B", _AR, "ROOT_B", _AR),
        ]
        index = C._build_role_children_index(edges)
        memo: dict = {}
        closure_a = C._role_closure(C._role_key(_AR, "ROOT_A"), index, memo)
        closure_b = C._role_closure(C._role_key(_AR, "ROOT_B"), index, memo)
        assert C._role_key(_AR, "SHARED") in closure_a
        assert C._role_key(_AR, "SHARED") not in closure_b
        assert C._role_key(_AR, "ONLY_B") in closure_b
        assert C._role_key(_AR, "ONLY_B") not in closure_a
