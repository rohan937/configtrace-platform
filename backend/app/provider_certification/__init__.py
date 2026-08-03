"""Provider Certification Framework (message 1 of N).

Provider-agnostic system that evaluates a provider's DECLARED contract
(a ``ProviderCertificationManifest``) against ACTUAL repository wiring
(discovered via ``app.provider_certification.discovery``) and produces a
deterministic, machine-readable certification result.

This package never calls external provider APIs, never reads customer
credentials, never mutates the database, and never triggers a sync. It
operates entirely on static repository structure: source modules,
capability-matrix entries, security-rule registries, and frontend source
text.

Provider expansion is frozen (Sentry, message 8, was the final planned
provider). This framework does not launch, migrate, or add providers —
it only certifies what already exists.
"""

from __future__ import annotations

SCHEMA_VERSION = 1
