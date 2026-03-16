"use node";

import { action } from "./_generated/server";
import { v } from "convex/values";

// ── Password check ──────────────────────────────────────────

function checkPassword(password: string): boolean {
  const expected = process.env.LOCKDOWN_PASSWORD;
  if (!expected) throw new Error("LOCKDOWN_PASSWORD not configured");
  return password === expected;
}

function requireAuth(password: string) {
  if (!checkPassword(password)) throw new Error("Unauthorized");
}

// ── Request log ─────────────────────────────────────────────

interface RequestLog {
  method: string;
  url: string;
  status: number | null;
  duration: number;
  size: number | null;
}

const requestLog: RequestLog[] = [];

function resetLog() {
  requestLog.length = 0;
}

function collectLog(): RequestLog[] {
  return [...requestLog];
}

// ── HTTP helpers ────────────────────────────────────────────

interface FetchResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  ok: boolean;
  size: number;
}

async function safeFetch(url: string, options?: RequestInit): Promise<FetchResult | null> {
  const method = (options?.method || "GET").toUpperCase();
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Lockdown-Scanner/1.0 (security audit tool; +https://lockdown.neorgon.com)",
        ...((options?.headers as Record<string, string>) || {}),
      },
    });
    clearTimeout(timeout);
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((val, key) => { headers[key.toLowerCase()] = val; });
    const duration = Date.now() - start;
    requestLog.push({ method, url, status: res.status, duration, size: body.length });
    return { status: res.status, headers, body, ok: res.ok, size: body.length };
  } catch {
    const duration = Date.now() - start;
    requestLog.push({ method, url, status: null, duration, size: null });
    return null;
  }
}

async function headFetch(url: string): Promise<FetchResult | null> {
  let res = await safeFetch(url, { method: "HEAD" });
  if (!res || res.status === 405) {
    res = await safeFetch(url, { method: "GET" });
  }
  return res;
}

// ── Finding shape ───────────────────────────────────────────

interface Finding {
  severity: "critical" | "warning" | "info" | "pass";
  title: string;
  detail?: string;
  endpoint?: string;
  hardening?: string;
}

interface ScanResult {
  findings: Finding[];
  requests: RequestLog[];
}

// ── Verify password action ──────────────────────────────────

export const verifyPassword = action({
  args: { password: v.string() },
  handler: async (_, { password }): Promise<boolean> => {
    return checkPassword(password);
  },
});

// ── Probe exposed files ─────────────────────────────────────

// Three tiers:
//   critical — secrets, credentials, database dumps (should NEVER be public)
//   warning  — config/metadata that leaks details (risky but not secrets)
//   info     — manifests/build files (expected in some setups, worth noting)

const SENSITIVE_FILES: { path: string; label: string; tier: "critical" | "warning" | "info" }[] = [
  // Critical — secrets & credentials
  { path: "/.env", label: ".env (environment variables)", tier: "critical" },
  { path: "/.env.local", label: ".env.local (local env)", tier: "critical" },
  { path: "/.env.production", label: ".env.production", tier: "critical" },
  { path: "/.git/config", label: ".git/config (repository config)", tier: "critical" },
  { path: "/.git/HEAD", label: ".git/HEAD (git metadata)", tier: "critical" },
  { path: "/.htpasswd", label: ".htpasswd (Apache passwords)", tier: "critical" },
  { path: "/.npmrc", label: ".npmrc (npm config, may contain tokens)", tier: "critical" },
  { path: "/phpinfo.php", label: "PHP info page", tier: "critical" },
  { path: "/server-status", label: "Apache server status", tier: "critical" },
  { path: "/server-info", label: "Apache server info", tier: "critical" },
  { path: "/backup.sql", label: "SQL backup file", tier: "critical" },
  { path: "/dump.sql", label: "SQL dump file", tier: "critical" },
  { path: "/database.sql", label: "Database file", tier: "critical" },
  { path: "/config.php", label: "PHP config file", tier: "critical" },
  { path: "/elmah.axd", label: "ELMAH error log (.NET)", tier: "critical" },
  { path: "/debug/", label: "Debug endpoint", tier: "critical" },
  { path: "/trace", label: "Trace endpoint", tier: "critical" },
  { path: "/_debug", label: "Debug endpoint", tier: "critical" },

  // Warning — config & metadata leakage
  { path: "/.DS_Store", label: ".DS_Store (macOS metadata)", tier: "warning" },
  { path: "/.htaccess", label: ".htaccess (Apache config)", tier: "warning" },
  { path: "/config.yml", label: "YAML config file", tier: "warning" },
  { path: "/config.json", label: "JSON config file", tier: "warning" },
  { path: "/web.config", label: "IIS web.config", tier: "warning" },
  { path: "/wp-admin/", label: "WordPress admin panel", tier: "warning" },
  { path: "/wp-login.php", label: "WordPress login page", tier: "warning" },
  { path: "/crossdomain.xml", label: "Flash crossdomain policy", tier: "warning" },

  // Info — manifests & build artifacts (common in public repos, not secrets)
  { path: "/package.json", label: "Node.js package manifest", tier: "info" },
  { path: "/composer.json", label: "Composer dependencies", tier: "info" },
  { path: "/Dockerfile", label: "Dockerfile", tier: "info" },
  { path: "/docker-compose.yml", label: "Docker Compose config", tier: "info" },
  { path: "/.dockerenv", label: ".dockerenv (container marker)", tier: "info" },
];

const TIER_HARDENING = {
  critical: (path: string) =>
    `Block access to ${path} immediately. This file can expose secrets, credentials, or sensitive data. Remove it from the public directory or deny access in your web server config.`,
  warning: (path: string) =>
    `Consider blocking ${path} from public access. It leaks implementation details that help attackers map your infrastructure.`,
  info: (path: string) =>
    `${path} is publicly visible. While not a secret, it reveals your tech stack. Consider whether this exposure is intentional.`,
};

export const probeFiles = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];

    const checks = SENSITIVE_FILES.map(async (file) => {
      const url = targetUrl + file.path;
      const res = await headFetch(url);
      if (res && res.ok && res.status === 200) {
        findings.push({
          severity: file.tier,
          title: `${file.label} is publicly accessible`,
          endpoint: file.path,
          detail: `HTTP ${res.status} — ${file.tier === "info" ? "discoverable file" : "should not be publicly reachable"}`,
          hardening: TIER_HARDENING[file.tier](file.path),
        });
      }
    });

    await Promise.all(checks);

    if (findings.length === 0) {
      findings.push({
        severity: "pass",
        title: "No common sensitive files found exposed",
        detail: `Checked ${SENSITIVE_FILES.length} paths. None returned HTTP 200.`,
      });
    }

    return { findings, requests: collectLog() };
  },
});

// ── Check security headers ──────────────────────────────────

const REQUIRED_HEADERS: { name: string; label: string; hardening: string }[] = [
  {
    name: "strict-transport-security",
    label: "Strict-Transport-Security (HSTS)",
    hardening: "Add header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
  },
  {
    name: "content-security-policy",
    label: "Content-Security-Policy (CSP)",
    hardening: "Define a CSP that restricts script-src, style-src, and default-src to trusted origins. Start with report-only mode to avoid breaking your site.",
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    hardening: "Add header: X-Content-Type-Options: nosniff",
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    hardening: "Add header: X-Frame-Options: DENY (or SAMEORIGIN if you embed your own iframes). Alternatively, use CSP frame-ancestors directive.",
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    hardening: "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=() to disable unused browser APIs.",
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    hardening: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    name: "x-xss-protection",
    label: "X-XSS-Protection",
    hardening: "Add header: X-XSS-Protection: 0 (modern browsers use CSP instead; the old filter can introduce vulnerabilities).",
  },
];

export const checkHeaders = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];

    const res = await safeFetch(targetUrl);
    if (!res) {
      findings.push({
        severity: "critical",
        title: "Could not reach the target URL",
        detail: "The server did not respond within 8 seconds.",
      });
      return { findings, requests: collectLog() };
    }

    if (targetUrl.startsWith("http://")) {
      findings.push({
        severity: "critical",
        title: "Site uses HTTP, not HTTPS",
        detail: "Traffic is unencrypted and vulnerable to interception.",
        hardening: "Enable HTTPS with a valid TLS certificate. Use HSTS to enforce HTTPS on all future visits. Most hosts (Cloudflare, Netlify, GitHub Pages) offer free TLS.",
      });
    } else {
      findings.push({
        severity: "pass",
        title: "Site uses HTTPS",
        detail: "Connection is encrypted with TLS.",
      });
    }

    for (const hdr of REQUIRED_HEADERS) {
      const val = res.headers[hdr.name];
      if (val) {
        findings.push({
          severity: "pass",
          title: `${hdr.label} is set`,
          detail: `Value: ${val.substring(0, 120)}${val.length > 120 ? "..." : ""}`,
        });
      } else {
        findings.push({
          severity: "warning",
          title: `Missing ${hdr.label}`,
          detail: "This security header is not present in the response.",
          hardening: hdr.hardening,
        });
      }
    }

    return { findings, requests: collectLog() };
  },
});

// ── Check robots.txt and sitemap ────────────────────────────

export const checkRobots = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];

    const robotsRes = await safeFetch(targetUrl + "/robots.txt");
    if (!robotsRes || robotsRes.status !== 200) {
      findings.push({
        severity: "info",
        title: "No robots.txt found",
        endpoint: "/robots.txt",
        detail: "Search engines will crawl all pages by default.",
        hardening: "Create a robots.txt to control which pages bots can access. Even a minimal one (User-agent: * / Allow: /) signals intentional configuration.",
      });
    } else {
      findings.push({
        severity: "pass",
        title: "robots.txt exists",
        endpoint: "/robots.txt",
        detail: `${robotsRes.body.length} bytes`,
      });

      const body = robotsRes.body.toLowerCase();
      if (body.includes("disallow:") && body.includes("/api")) {
        findings.push({
          severity: "info",
          title: "robots.txt blocks /api paths",
          detail: "This hides API routes from search engines but does not block direct access. Ensure API authentication is in place.",
        });
      }
      const lines = robotsRes.body.split("\n");
      const blockAll = lines.some(l => /^disallow:\s*\/\s*$/i.test(l.trim()));
      if (blockAll) {
        findings.push({
          severity: "warning",
          title: "robots.txt blocks all crawlers",
          detail: "Disallow: / prevents all search engines from indexing your site.",
          hardening: "If this is intentional (staging site), add a noindex meta tag too. For production sites, specify only sensitive paths in Disallow.",
        });
      }
    }

    const sitemapRes = await safeFetch(targetUrl + "/sitemap.xml");
    if (!sitemapRes || sitemapRes.status !== 200) {
      findings.push({
        severity: "info",
        title: "No sitemap.xml found",
        endpoint: "/sitemap.xml",
        detail: "Search engines rely on sitemaps to discover pages efficiently.",
        hardening: "Create a sitemap.xml listing all public URLs. Reference it in robots.txt with: Sitemap: https://yoursite.com/sitemap.xml",
      });
    } else {
      findings.push({
        severity: "pass",
        title: "sitemap.xml exists",
        endpoint: "/sitemap.xml",
        detail: `${sitemapRes.body.length} bytes`,
      });
    }

    return { findings, requests: collectLog() };
  },
});

// ── Check SEO basics ────────────────────────────────────────

export const checkSeo = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];

    const res = await safeFetch(targetUrl);
    if (!res) return { findings, requests: collectLog() };

    const html = res.body;

    const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    if (!titleMatch || !titleMatch[1].trim()) {
      findings.push({
        severity: "warning",
        title: "Missing or empty <title> tag",
        hardening: "Add a descriptive <title> under 60 characters. Format: Page Name - Site Name",
      });
    } else {
      const title = titleMatch[1].trim();
      findings.push({
        severity: title.length > 60 ? "info" : "pass",
        title: "Title tag present",
        detail: `"${title}" (${title.length} chars${title.length > 60 ? ", consider shortening to 60" : ""})`,
      });
    }

    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
    if (!descMatch || !descMatch[1].trim()) {
      findings.push({
        severity: "warning",
        title: "Missing meta description",
        hardening: "Add a <meta name='description' content='...'> under 155 characters with active verbs describing what the page does.",
      });
    } else {
      const desc = descMatch[1].trim();
      findings.push({
        severity: desc.length > 155 ? "info" : "pass",
        title: "Meta description present",
        detail: `${desc.length} chars${desc.length > 155 ? " (over 155, may be truncated)" : ""}`,
      });
    }

    const hasOgTitle = /<meta[^>]+property=["']og:title["']/i.test(html);
    const hasOgDesc = /<meta[^>]+property=["']og:description["']/i.test(html);
    const hasOgImage = /<meta[^>]+property=["']og:image["']/i.test(html);

    if (!hasOgTitle || !hasOgDesc) {
      findings.push({
        severity: "warning",
        title: "Missing Open Graph tags",
        detail: `Missing: ${[!hasOgTitle && "og:title", !hasOgDesc && "og:description"].filter(Boolean).join(", ")}`,
        hardening: "Add og:title, og:description, and og:image meta tags for rich previews when shared on social media.",
      });
    } else {
      findings.push({ severity: "pass", title: "Open Graph title and description present" });
    }
    if (!hasOgImage) {
      findings.push({
        severity: "info",
        title: "No og:image tag found",
        detail: "Social shares will not show a preview image.",
        hardening: "Add a 1200x630 PNG og:image for rich social previews.",
      });
    }

    const hasViewport = /<meta[^>]+name=["']viewport["']/i.test(html);
    findings.push(hasViewport
      ? { severity: "pass", title: "Viewport meta tag present" }
      : { severity: "warning", title: "Missing viewport meta tag", hardening: "Add <meta name='viewport' content='width=device-width, initial-scale=1.0'> for mobile responsiveness." }
    );

    const hasCanonical = /<link[^>]+rel=["']canonical["']/i.test(html);
    findings.push(hasCanonical
      ? { severity: "pass", title: "Canonical URL set" }
      : { severity: "info", title: "No canonical URL", hardening: "Add <link rel='canonical' href='https://yoursite.com/'> to prevent duplicate content issues." }
    );

    const hasFavicon = /<link[^>]+rel=["'](?:icon|shortcut icon)["']/i.test(html);
    findings.push(hasFavicon
      ? { severity: "pass", title: "Favicon linked" }
      : { severity: "info", title: "No favicon link tag", hardening: "Add <link rel='icon' href='/favicon.ico'> so browsers show your icon in tabs." }
    );

    return { findings, requests: collectLog() };
  },
});

// ── Probe API endpoints ─────────────────────────────────────

const API_PATHS = [
  { path: "/api", label: "REST API root" },
  { path: "/api/v1", label: "API v1" },
  { path: "/api/v2", label: "API v2" },
  { path: "/graphql", label: "GraphQL endpoint" },
  { path: "/graphiql", label: "GraphiQL IDE" },
  { path: "/swagger", label: "Swagger UI" },
  { path: "/swagger.json", label: "Swagger JSON spec" },
  { path: "/openapi.json", label: "OpenAPI spec" },
  { path: "/docs", label: "API docs" },
  { path: "/api-docs", label: "API documentation" },
  { path: "/api/docs", label: "API documentation" },
  { path: "/health", label: "Health check" },
  { path: "/healthz", label: "Health check (K8s)" },
  { path: "/status", label: "Status endpoint" },
  { path: "/metrics", label: "Metrics (Prometheus)" },
  { path: "/actuator", label: "Spring Boot Actuator" },
  { path: "/actuator/health", label: "Spring Boot Health" },
  { path: "/actuator/env", label: "Spring Boot Env (critical)" },
  { path: "/admin", label: "Admin panel" },
  { path: "/admin/", label: "Admin panel" },
  { path: "/_admin", label: "Admin panel" },
  { path: "/console", label: "Console" },
  { path: "/debug/vars", label: "Go debug vars" },
  { path: "/debug/pprof", label: "Go profiler" },
];

export const probeEndpoints = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];
    const discovered: string[] = [];

    const criticalPaths = ["/actuator/env", "/debug/vars", "/debug/pprof", "/metrics", "/console"];

    const checks = API_PATHS.map(async (ep) => {
      const url = targetUrl + ep.path;
      const res = await headFetch(url);
      if (res && res.ok && res.status === 200) {
        const isCritical = criticalPaths.includes(ep.path);
        discovered.push(ep.path);
        findings.push({
          severity: isCritical ? "critical" : "warning",
          title: `${ep.label} is publicly accessible`,
          endpoint: ep.path,
          detail: `HTTP ${res.status}. This endpoint may expose internal information or allow unauthorized actions.`,
          hardening: isCritical
            ? `This endpoint exposes sensitive internal data. Block it immediately with firewall rules, authentication middleware, or remove it from production.`
            : `If this endpoint is intentional, ensure it requires authentication. If not needed publicly, block it via reverse proxy rules or remove it. Consider IP allowlisting for internal endpoints.`,
        });
      }
    });

    await Promise.all(checks);

    if (discovered.length === 0) {
      findings.push({
        severity: "pass",
        title: "No common API/admin endpoints found exposed",
        detail: `Probed ${API_PATHS.length} common paths. None returned HTTP 200.`,
      });
    } else {
      findings.unshift({
        severity: "info",
        title: `${discovered.length} endpoint(s) discovered`,
        detail: `Found: ${discovered.join(", ")}`,
        hardening: "Review each endpoint below. Ensure all require authentication or are intentionally public. Use rate limiting on public APIs.",
      });
    }

    return { findings, requests: collectLog() };
  },
});

// ── Check information leakage ───────────────────────────────

export const checkLeakage = action({
  args: { targetUrl: v.string(), password: v.string() },
  handler: async (_, { targetUrl, password }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];

    const res = await safeFetch(targetUrl);
    if (!res) return { findings, requests: collectLog() };

    const server = res.headers["server"];
    if (server) {
      const hasVersion = /\/[\d.]+/.test(server);
      findings.push({
        severity: hasVersion ? "warning" : "info",
        title: `Server header: ${server}`,
        detail: hasVersion
          ? "The server header includes a version number, which helps attackers find known vulnerabilities."
          : "Server type is disclosed but without a version number.",
        hardening: hasVersion
          ? "Remove the version number from the Server header. In Nginx: server_tokens off; In Apache: ServerTokens Prod;"
          : "Consider removing the Server header entirely to reduce fingerprinting surface.",
      });
    } else {
      findings.push({ severity: "pass", title: "Server header not disclosed" });
    }

    const poweredBy = res.headers["x-powered-by"];
    if (poweredBy) {
      findings.push({
        severity: "warning",
        title: `X-Powered-By header: ${poweredBy}`,
        detail: "Reveals the backend technology stack, helping attackers target known vulnerabilities.",
        hardening: "Remove the X-Powered-By header. In Express: app.disable('x-powered-by'); In PHP: expose_php = Off in php.ini",
      });
    } else {
      findings.push({ severity: "pass", title: "X-Powered-By header not disclosed" });
    }

    const html = res.body.toLowerCase();
    const debugPatterns = [
      { pattern: "stack trace", label: "Stack trace detected in page" },
      { pattern: "traceback (most recent", label: "Python traceback detected" },
      { pattern: "fatal error:", label: "PHP fatal error detected" },
      { pattern: "exception in thread", label: "Java exception detected" },
      { pattern: "syntax error", label: "Syntax error exposed" },
    ];

    for (const dp of debugPatterns) {
      if (html.includes(dp.pattern)) {
        findings.push({
          severity: "critical",
          title: dp.label,
          detail: "Error details are visible in the page HTML. This exposes internal paths, line numbers, and potentially sensitive data.",
          hardening: "Disable debug mode in production. Show generic error pages to users and log detailed errors server-side only.",
        });
      }
    }

    const secretPatterns = [
      { pattern: /sk[-_]live[-_][a-zA-Z0-9]{20,}/i, label: "Possible Stripe live secret key in page source" },
      { pattern: /AKIA[A-Z0-9]{16}/i, label: "Possible AWS access key in page source" },
      { pattern: /ghp_[a-zA-Z0-9]{36}/i, label: "Possible GitHub personal access token in page source" },
    ];

    for (const sp of secretPatterns) {
      if (sp.pattern.test(res.body)) {
        findings.push({
          severity: "critical",
          title: sp.label,
          detail: "A pattern matching a known secret format was found in the page HTML. Verify and rotate the credential immediately.",
          hardening: "Never embed API keys or tokens in client-side code. Use server-side proxy endpoints or environment variables. Rotate the exposed credential now.",
        });
      }
    }

    if (findings.every(f => f.severity === "pass")) {
      findings.push({ severity: "pass", title: "No obvious information leakage detected" });
    }

    return { findings, requests: collectLog() };
  },
});

// ── Endpoint fuzzer ─────────────────────────────────────────

const COMMON_RESOURCES = [
  "users", "user", "me", "profile", "accounts", "account",
  "admin", "admins", "roles", "permissions",
  "stats", "analytics", "metrics", "dashboard",
  "config", "settings", "env", "environment",
  "logs", "log", "events", "audit",
  "tokens", "sessions", "keys", "secrets",
  "files", "uploads", "images", "media",
  "orders", "payments", "invoices", "billing",
  "notifications", "messages", "emails",
  "search", "export", "import", "download", "backup",
  "debug", "test", "internal", "private", "hidden",
  "version", "info", "health", "status", "ping",
];

const COMMON_QUERY_PROBES = [
  "?page=1", "?limit=100", "?debug=true", "?verbose=1",
  "?format=json", "?include=all", "?admin=true",
  "?id=1", "?user=admin", "?role=admin",
];

const SENSITIVE_KEYWORDS = [
  "password", "secret", "token", "key", "credential",
  "auth", "session", "admin", "root", "debug",
  "internal", "private", "config", "database", "sql",
];

export const fuzzEndpoints = action({
  args: {
    targetUrl: v.string(),
    password: v.string(),
    basePaths: v.array(v.string()),
  },
  handler: async (_, { targetUrl, password, basePaths }): Promise<ScanResult> => {
    requireAuth(password);
    resetLog();
    const findings: Finding[] = [];
    const base = targetUrl.replace(/\/+$/, "");

    // Collect all URLs to probe
    const urlsToProbe: string[] = [];
    for (const bp of basePaths) {
      for (const resource of COMMON_RESOURCES) {
        urlsToProbe.push(`${base}${bp}/${resource}`);
      }
    }

    // Also try query parameter probes on base paths
    for (const bp of basePaths) {
      for (const qp of COMMON_QUERY_PROBES) {
        urlsToProbe.push(`${base}${bp}${qp}`);
      }
    }

    // Batch requests (10 at a time)
    const BATCH_SIZE = 10;
    const discovered: { url: string; status: number; size: number | null; hasBody: boolean; hasSensitive: boolean }[] = [];

    for (let i = 0; i < urlsToProbe.length; i += BATCH_SIZE) {
      const batch = urlsToProbe.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(async (url) => {
          const res = await safeFetch(url, { method: "GET", redirect: "follow" });
          if (!res) return null;
          const bodyText = res.body.substring(0, 2000);
          const hasSensitive = SENSITIVE_KEYWORDS.some(kw =>
            bodyText.toLowerCase().includes(kw)
          );
          return {
            url,
            status: res.status,
            size: res.size,
            hasBody: bodyText.length > 0 && !bodyText.includes("<!DOCTYPE") && !bodyText.includes("<html"),
            hasSensitive,
          };
        })
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value) {
          const v = r.value;
          // Only report endpoints that responded with success or interesting codes
          if (v.status >= 200 && v.status < 300) {
            discovered.push(v);
          } else if (v.status === 401 || v.status === 403) {
            // Protected but exists — noteworthy
            discovered.push(v);
          }
        }
      }
    }

    // Generate findings from discovered endpoints
    for (const d of discovered) {
      const shortUrl = d.url.replace(base, "");

      if (d.hasSensitive && d.status >= 200 && d.status < 300) {
        findings.push({
          severity: "critical",
          title: `Sensitive data exposed at ${shortUrl}`,
          endpoint: d.url,
          detail: `Returned ${d.status} with content containing sensitive keywords (password, token, key, etc.). An attacker could extract credentials or internal data.`,
          hardening: "Require authentication for all sensitive endpoints. Never expose credentials, tokens, or internal configuration via unauthenticated API routes.",
        });
      } else if (d.status >= 200 && d.status < 300 && d.hasBody) {
        findings.push({
          severity: "warning",
          title: `Discoverable endpoint: ${shortUrl}`,
          endpoint: d.url,
          detail: `Returned ${d.status} with a non-HTML response body (${d.size !== null ? d.size + " bytes" : "unknown size"}). This endpoint is publicly accessible and could leak data.`,
          hardening: "Restrict API endpoints with authentication. If public by design, ensure no sensitive data is returned. Consider rate limiting.",
        });
      } else if (d.status === 401 || d.status === 403) {
        findings.push({
          severity: "info",
          title: `Protected endpoint exists: ${shortUrl}`,
          endpoint: d.url,
          detail: `Returned ${d.status} (${d.status === 401 ? "Unauthorized" : "Forbidden"}). The endpoint exists but requires credentials. An attacker now knows this path exists.`,
          hardening: "Return 404 instead of 401/403 for sensitive endpoints to avoid path enumeration. Or use a WAF to block scanning attempts.",
        });
      }
    }

    if (!findings.length) {
      findings.push({
        severity: "pass",
        title: "No additional endpoints discovered via fuzzing",
        detail: `Tested ${urlsToProbe.length} URL combinations across ${basePaths.length} base paths. No accessible or sensitive endpoints found.`,
      });
    }

    return { findings, requests: collectLog() };
  },
});
