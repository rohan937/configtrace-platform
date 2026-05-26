// ConfigTrace service worker — M58.7 (Browser Push Notifications)
//
// Handles Web Push API events for the ConfigTrace PWA.
// This file must live at the web root (/sw.js) so its scope covers the
// entire origin.  The Next.js headers config sets Service-Worker-Allowed: /
// and Cache-Control: no-cache so updates are picked up on next page load.
//
// SECURITY: No credentials or PII are stored in this file.
// Push payload fields: title, body, url, tag, risk_level, provider.

"use strict";

// ── Push event ────────────────────────────────────────────────────────────────
// Fired when the backend sends a push message.

self.addEventListener("push", function (event) {
  if (!event.data) return;

  var payload = {};
  try {
    payload = event.data.json();
  } catch (_) {
    // Fallback: treat raw text as notification body.
    payload = { title: "ConfigTrace Alert", body: event.data.text() };
  }

  var title = payload.title || "ConfigTrace Alert";
  var body = payload.body || "";
  var url = payload.url || "/";
  var tag = payload.tag || "configtrace-alert";

  var options = {
    body: body,
    icon: "/icon-192.png",
    badge: "/icon-96.png",
    tag: tag,
    data: { url: url },
    requireInteraction: false,
    silent: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Notification click ────────────────────────────────────────────────────────
// Focus an existing tab showing the target URL, or open a new one.

self.addEventListener("notificationclick", function (event) {
  event.notification.close();

  var targetUrl = (event.notification.data && event.notification.data.url)
    ? event.notification.data.url
    : "/";

  event.waitUntil(
    clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then(function (clientList) {
        // Look for an existing window on the target URL.
        for (var i = 0; i < clientList.length; i++) {
          var client = clientList[i];
          if (client.url === targetUrl && "focus" in client) {
            return client.focus();
          }
        }
        // No existing window — open a new one.
        if (clients.openWindow) {
          return clients.openWindow(targetUrl);
        }
      })
  );
});

// ── Notification close ────────────────────────────────────────────────────────
// No action needed — analytics could go here in future.

self.addEventListener("notificationclose", function (_event) {
  // intentionally empty
});
