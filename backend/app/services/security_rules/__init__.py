"""Security exposure rules — M60.4.

Each provider module exposes ``evaluate(record) -> list[FindingCandidate]`` for
the normalized snapshot records it understands. Rules are deterministic and
conservative: they only fire on explicit, reliable normalized fields and never
inspect secrets, payloads, or customer data.

These produce *security exposure findings* from configuration state — they do
NOT detect breaches.
"""
