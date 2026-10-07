import type { Context } from "hono";
import type { Config } from "./config.ts";

/**
 * Response hardening for the API edge.
 *
 * The API previously sent only `X-Content-Type-Options`, `Referrer-Policy`
 * and `Cache-Control`. Signed file/preview/console links are bearer-equivalent
 * URLs that users open in a browser, so without framing and content policies
 * any third-party page could embed them (clickjacking) and any injected markup
 * in an HTML response would run unsandboxed.
 *
 * Two first-party embeds constrain the design, both verified in the clients:
 * - `apps/mobile/src/BrowserConsole.web.tsx` loads `/api/browsers/:id/console`
 *   in an `<iframe>` from the web-app origin.
 * - `apps/mobile/src/PdfReader.web.tsx` loads `/api/files/:id/content` (PDF)
 *   in an `<iframe>` from the web-app origin.
 * A blanket `DENY`/`SAMEORIGIN` would break those embeds because the web app
 * runs on a different origin than the API, so framing is restricted with a
 * `frame-ancestors` allowlist built from the configured clients instead, and
 * byte responses (PDF/PNG) carry framing protection only — no content
 * directives that could interfere with plugin/image rendering.
 */

/** First-party origins permitted to frame API responses. */
export function frameAncestorSources(config: Config): string[] {
  const sources = ["'self'"];
  for (const entry of [...config.allowedOrigins, config.publicUrl]) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    try {
      const origin = new URL(trimmed).origin;
      if (origin !== "null" && !sources.includes(origin)) sources.push(origin);
    } catch {
      // Unparseable entries never match an Origin header either; leaving them
      // out keeps the directive valid instead of breaking the whole header.
    }
  }
  return sources;
}

export function frameAncestorsDirective(config: Config): string {
  return `frame-ancestors ${frameAncestorSources(config).join(" ")}`;
}

/** Directives preserved from the browser-console route when it is centralized here. */
export const consoleContentPolicyBase =
  "default-src 'self'; img-src 'self' blob:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";

export function contentSecurityPolicy(method: string, path: string, config: Config): string {
  const framing = frameAncestorsDirective(config);
  // The console is an HTML page that fetches its preview over the network, so
  // it keeps its script/style allowances and only gains framing protection.
  if (method === "GET" && /^\/api\/browsers\/[^/]+\/console$/.test(path))
    return `${consoleContentPolicyBase}; ${framing}`;
  // Byte responses: framing protection only, so plugin/image rendering is untouched.
  if (
    method === "GET" &&
    (/^\/api\/files\/[^/]+\/content$/.test(path) || /^\/api\/browsers\/[^/]+\/preview$/.test(path))
  )
    return framing;
  // JSON, OAuth pages, and everything else: nothing may load or submit anywhere.
  return `default-src 'none'; base-uri 'none'; form-action 'none'; ${framing}`;
}

/** Headers that are identical on every response. */
export function baseSecurityHeaders(config: Config): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    // The API serves data, never media capture: deny the powerful features outright.
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), " +
      "magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), " +
      "autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=()",
  };
  // Browsers ignore HSTS on plaintext, and emitting it there would be a lie in
  // local/sample setups, so only advertise it when the public URL is https.
  try {
    if (new URL(config.publicUrl).protocol === "https:")
      headers["Strict-Transport-Security"] = "max-age=15552000; includeSubDomains";
  } catch {
    // An invalid public URL fails fast in createApp before this ever matters.
  }
  return headers;
}

/**
 * Sets hardening headers on every response, including error responses produced
 * by `onError`. Handlers that return a raw `Response` (the CopilotKit stream
 * passthrough) bypass context headers and must apply these explicitly.
 */
export function securityHeaders(config: Config) {
  const base = baseSecurityHeaders(config);
  return async (c: Context, next: () => Promise<void>) => {
    for (const [name, value] of Object.entries(base)) c.header(name, value);
    c.header("Content-Security-Policy", contentSecurityPolicy(c.req.method, c.req.path, config));
    await next();
  };
}
