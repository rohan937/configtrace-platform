"use client";

/**
 * CreateCaseButton (M66.8).
 *
 * Spins up a human investigation case from a signal or correlation, linking its
 * evidence, then navigates to the new case. Used on the Signal and Correlation
 * detail pages.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import { createCaseFromSignal, createCaseFromCorrelation } from "@/lib/api";

export default function CreateCaseButton({
  from,
  id,
}: {
  from: "signal" | "correlation";
  id: string;
}) {
  const { getToken } = useAuth();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onClick = async () => {
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      const created =
        from === "signal"
          ? await createCaseFromSignal(id, token)
          : await createCaseFromCorrelation(id, token);
      router.push(`/security/cases/${created.id}`);
    } catch {
      setError("Could not create case. Please try again.");
      setBusy(false);
    }
  };

  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
      <button
        onClick={onClick}
        disabled={busy}
        style={{
          fontSize: "12.5px",
          fontWeight: 500,
          color: "#0b0d12",
          background: "#6b9cf8",
          border: "none",
          padding: "7px 14px",
          borderRadius: "8px",
          cursor: busy ? "not-allowed" : "pointer",
          opacity: busy ? 0.7 : 1,
          whiteSpace: "nowrap",
        }}
      >
        {busy ? "Creating case…" : `Create case from ${from}`}
      </button>
      {error && <span style={{ fontSize: "12px", color: "#e84040" }}>{error}</span>}
    </span>
  );
}
