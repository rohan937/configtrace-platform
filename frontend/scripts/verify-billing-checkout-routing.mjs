#!/usr/bin/env node
/**
 * Narrowest-appropriate regression guard for the billing checkout routing
 * fix (no frontend test framework exists in this repo — see package.json).
 *
 * Statically asserts, against the actual source text of the billing page,
 * that Pro/Team upgrades call the provider-neutral checkout functions and
 * never the legacy Stripe-only one inside `handleUpgrade` — this is
 * exactly the regression class that shipped to production (Pro/Team
 * buttons silently falling back to POST /billing/checkout, which ignores
 * DODO_PILOT_WORKSPACE_ID and never emits a pilot_override_applied audit
 * event).
 *
 * Zero dependencies. Run with: node scripts/verify-billing-checkout-routing.mjs
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PAGE_PATH = path.join(
  __dirname,
  "..",
  "src/app/(app)/settings/workspace/billing/page.tsx",
);

const source = readFileSync(PAGE_PATH, "utf8");

/** @type {string[]} */
const failures = [];

function assert(condition, message) {
  if (!condition) failures.push(message);
}

// 1. The provider-neutral functions must be imported.
assert(
  /import\s*\{[^}]*createProCheckout[^}]*\}\s*from\s*"@\/lib\/api"/s.test(source),
  "createProCheckout is not imported from @/lib/api",
);
assert(
  /import\s*\{[^}]*createTeamCheckout[^}]*\}\s*from\s*"@\/lib\/api"/s.test(source),
  "createTeamCheckout is not imported from @/lib/api",
);

// 2. The legacy Stripe-only checkout function must NOT be imported at all
//    (it must not be reachable from the Pro/Team upgrade path — if it is
//    ever legitimately needed again, it should be imported and its call
//    site should be reviewed, not silently reintroduced).
assert(
  !/import\s*\{[^}]*\bcreateCheckoutSession\b[^}]*\}\s*from\s*"@\/lib\/api"/s.test(source),
  "createCheckoutSession (legacy /billing/checkout) must not be imported into the billing page",
);
assert(
  !source.includes("createCheckoutSession("),
  "createCheckoutSession (legacy /billing/checkout) must not be called anywhere in the billing page",
);

// 3. handleUpgrade must call both provider-neutral functions, keyed on
//    the "pro" | "team" plan argument, not on a pre-read provider field.
const handleUpgradeMatch = source.match(
  /async function handleUpgrade\(plan: BillingPlan\) \{[\s\S]*?\n  \}\n/,
);
assert(handleUpgradeMatch, "Could not locate handleUpgrade function body");
if (handleUpgradeMatch) {
  const body = handleUpgradeMatch[0];
  assert(
    body.includes("createProCheckout(selectedWorkspace.id, token)"),
    "handleUpgrade does not call createProCheckout",
  );
  assert(
    body.includes("createTeamCheckout(selectedWorkspace.id, token)"),
    "handleUpgrade does not call createTeamCheckout",
  );
  assert(
    !body.includes("checkout_provider"),
    "handleUpgrade must not branch on a pre-read checkout_provider field before calling the checkout API",
  );
  assert(
    !body.includes("createCheckoutSession"),
    "handleUpgrade must not call the legacy createCheckoutSession",
  );
}

// 4. The single post-response completion path must redirect to
//    checkout_url for any provider that doesn't return a Paddle overlay
//    reference, and must never leave actionBusy stuck without setting an
//    error on failure.
const completeCheckoutMatch = source.match(
  /async function completeCheckout\([\s\S]*?\n  \}\n/,
);
assert(completeCheckoutMatch, "Could not locate completeCheckout function body");
if (completeCheckoutMatch) {
  const body = completeCheckoutMatch[0];
  assert(
    body.includes("window.location.href = response.checkout_url"),
    "completeCheckout does not redirect to response.checkout_url",
  );
  assert(
    body.includes('response.provider === "paddle"'),
    "completeCheckout does not special-case Paddle from the actual response (not a pre-guess)",
  );
}

// 5. The catch block in handleUpgrade itself — the one path that fires
//    when createProCheckout/createTeamCheckout rejects before any
//    response is available — must clear actionBusy and show an error.
//    (completeCheckout's own internal try/catch is for the Paddle-overlay
//    fallback only, and intentionally does not touch actionBusy — the
//    overlay stays open — so it is checked separately, not by this rule.)
if (handleUpgradeMatch) {
  const body = handleUpgradeMatch[0];
  const catchBlock = body.match(/catch \(err\) \{[\s\S]*?\n    \}/);
  assert(catchBlock, "handleUpgrade has no catch block");
  if (catchBlock) {
    assert(
      catchBlock[0].includes("setActionError(") && catchBlock[0].includes("setActionBusy(false)"),
      `handleUpgrade's catch block does not both show an error and clear the busy state:\n${catchBlock[0]}`,
    );
  }
}

if (failures.length > 0) {
  console.error("FAILED billing checkout routing checks:\n");
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log(`OK — ${PAGE_PATH} routes Pro/Team upgrades through provider-neutral checkout.`);
