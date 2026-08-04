/**
 * Paddle.js client integration (Commercial Infrastructure message 2).
 *
 * No @paddle/paddle-js npm package is added — Paddle.js is loaded via its
 * official CDN script tag exactly as Paddle's own documentation
 * recommends, matching this repo's existing pattern of preferring
 * dependency-free integrations where a small script load suffices
 * (see backend/app/billing/paddle_client.py's equivalent "no SDK" choice).
 *
 * Security
 * --------
 * - Only `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` (a public, client-safe token by
 *   Paddle's own design) is ever used here — never an API key or webhook
 *   secret, which only ever exist on the backend/Render.
 * - The backend creates the actual transaction (server-side pricing,
 *   authorization, custom_data correlation); this module only opens the
 *   Paddle-hosted checkout overlay for a transaction ID the backend
 *   already authorized — it never lets the client choose an arbitrary
 *   price or quantity.
 */

declare global {
  interface Window {
    Paddle?: {
      Environment: { set: (env: "sandbox" | "production") => void };
      Initialize: (options: { token: string; eventCallback?: (event: PaddleCheckoutEvent) => void }) => void;
      Checkout: {
        open: (options: { transactionId?: string; settings?: Record<string, unknown> }) => void;
      };
    };
  }
}

export interface PaddleCheckoutEvent {
  name: string;
  data?: Record<string, unknown>;
}

const PADDLE_SCRIPT_URL = "https://cdn.paddle.com/paddle/v2/paddle.js";

let scriptLoadPromise: Promise<void> | null = null;
let initialized = false;

/** Load the Paddle.js script exactly once, idempotently — a second call
 * while loading (or after loaded) returns the same promise/resolves
 * immediately, never inserting a duplicate <script> tag. */
export function loadPaddleScript(): Promise<void> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("Paddle.js can only be loaded in a browser context."));
  }
  if (window.Paddle) {
    return Promise.resolve();
  }
  if (scriptLoadPromise) {
    return scriptLoadPromise;
  }
  scriptLoadPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector(`script[src="${PADDLE_SCRIPT_URL}"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error("Failed to load Paddle.js.")));
      return;
    }
    const script = document.createElement("script");
    script.src = PADDLE_SCRIPT_URL;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load Paddle.js."));
    document.head.appendChild(script);
  });
  return scriptLoadPromise;
}

/** Initialize Paddle.js exactly once per page load — a second call is a
 * no-op (never re-initializes, which Paddle.js does not support safely). */
export async function initPaddle(
  environment: "sandbox" | "production",
  clientToken: string,
  eventCallback?: (event: PaddleCheckoutEvent) => void,
): Promise<void> {
  if (!clientToken) {
    throw new Error("Paddle client token is not configured (NEXT_PUBLIC_PADDLE_CLIENT_TOKEN missing).");
  }
  await loadPaddleScript();
  if (!window.Paddle) {
    throw new Error("Paddle.js loaded but window.Paddle is unavailable.");
  }
  if (initialized) {
    return;
  }
  if (environment === "sandbox") {
    window.Paddle.Environment.set("sandbox");
  }
  window.Paddle.Initialize({ token: clientToken, eventCallback });
  initialized = true;
}

/** Open the Paddle checkout overlay for a transaction ID the backend has
 * already created and authorized. Never accepts a price ID or quantity
 * directly — those are always server-computed (message-2 spec item 10). */
export function openPaddleCheckout(transactionId: string): void {
  if (!window.Paddle) {
    throw new Error("Paddle.js is not initialized.");
  }
  window.Paddle.Checkout.open({ transactionId });
}

export function isPaddleClientConfigured(): boolean {
  return Boolean(process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN);
}

export function paddleEnvironment(): "sandbox" | "production" {
  return process.env.NEXT_PUBLIC_PADDLE_ENVIRONMENT === "production" ? "production" : "sandbox";
}
