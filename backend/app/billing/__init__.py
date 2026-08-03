"""Provider-neutral commercial/billing domain (Commercial Infrastructure message 1).

Everything in this package is provider-agnostic: no module here imports the
Stripe SDK, calls a Stripe or Paddle API, or leaks a provider-specific type
(a Stripe ``Session``/``Price``/``Subscription`` object) across its public
surface. Provider-specific behavior lives only in ``app.billing.adapters``.

This is a NEW, additive domain layered on top of the existing
``app.services.billing_service`` / ``app.models.billing.WorkspaceBilling``
Stripe-coupled implementation — message 1 isolates and wraps that existing
code behind a provider interface, it does not replace or delete it. See
``backend/tests/reports/commercial_infrastructure_message1.md`` for the full
architecture writeup.
"""
