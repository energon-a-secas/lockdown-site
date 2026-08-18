// ── Convex client layer ──────────────────────────────────────
// Lazy-loads Convex SDK and exposes scan + auth functions.

let client = null;
let ConvexHttpClient = null;

const CONVEX_URL = 'https://dutiful-elephant-373.convex.cloud';

// Sent with every scan action; the deployment refuses calls without it.
//
// This is a speed bump, not authentication — it ships in public JS, so anyone
// reading this file can extract it. What it buys is that the scan endpoint is
// not usable by pointing a script at the deployment URL alone, and it can be
// rotated (`npx convex env set SCAN_SECRET <new>` + change here) if abused.
// The controls that actually bound the damage are server-side: the SSRF guard
// in convex/lib/guard.ts and the per-caller rate limit.
const SCAN_SECRET = 'lockdown-web-v1';

export async function initConvex() {
  if (client) return;
  try {
    const mod = await import('https://esm.sh/convex@1.21.0/browser');
    ConvexHttpClient = mod.ConvexHttpClient;
    if (CONVEX_URL) {
      client = new ConvexHttpClient(CONVEX_URL);
    }
  } catch (e) {
    console.warn('Convex SDK load failed, scans will not work:', e.message);
  }
}

function getClient() {
  if (!client) throw new Error('Scanner backend not connected. Set CONVEX_URL in data.js.');
  return client;
}

export async function runScan(targetUrl, onProgress, fuzzBasePaths) {
  const c = getClient();
  const allRequests = [];

  async function runAction(name, label, pct) {
    onProgress(label, pct);
    const result = await c.action(`scanner:${name}`, { targetUrl, scanSecret: SCAN_SECRET });
    if (result.requests) allRequests.push(...result.requests);
    return result.findings;
  }

  const files = await runAction('probeFiles', 'Probing exposed files...', 8);
  const headers = await runAction('checkHeaders', 'Checking security headers...', 22);
  const robots = await runAction('checkRobots', 'Analyzing robots.txt and sitemap...', 36);
  const seo = await runAction('checkSeo', 'Scanning for SEO basics...', 50);
  const endpoints = await runAction('probeEndpoints', 'Discovering API endpoints...', 64);
  const leakage = await runAction('checkLeakage', 'Checking information leakage...', 78);

  // Endpoint fuzzing
  const paths = fuzzBasePaths && fuzzBasePaths.length ? fuzzBasePaths : ['/api', '/api/v1', '/api/v2'];
  onProgress(`Fuzzing ${paths.length} base paths...`, 88);
  const fuzzResult = await c.action('scanner:fuzzEndpoints', {
    targetUrl, basePaths: paths, scanSecret: SCAN_SECRET,
  });
  if (fuzzResult.requests) allRequests.push(...fuzzResult.requests);
  const fuzz = fuzzResult.findings;

  onProgress('Compiling report...', 100);

  return {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    categories: { files, headers, robots, seo, endpoints, fuzz, leakage },
    requests: allRequests,
  };
}
