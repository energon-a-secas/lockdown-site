// ── Convex client layer ──────────────────────────────────────
// Lazy-loads Convex SDK and exposes scan + auth functions.

let client = null;
let ConvexHttpClient = null;
let api = null;

const CONVEX_URL = ''; // Set after `npx convex dev` or deploy

export async function initConvex() {
  if (client) return;
  try {
    const mod = await import('https://esm.sh/convex@1.21.0/browser');
    ConvexHttpClient = mod.ConvexHttpClient;
    // We'll use action calls with the URL set in the convex deployment
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

export async function verifyPassword(password) {
  const c = getClient();
  return await c.action('scanner:verifyPassword', { password });
}

export async function runScan(targetUrl, password, onProgress) {
  const c = getClient();

  // Run probe scan (exposed files, endpoints)
  onProgress('Probing exposed files...', 10);
  const fileResults = await c.action('scanner:probeFiles', { targetUrl, password });

  onProgress('Checking security headers...', 30);
  const headerResults = await c.action('scanner:checkHeaders', { targetUrl, password });

  onProgress('Analyzing robots.txt and sitemap...', 50);
  const robotsResults = await c.action('scanner:checkRobots', { targetUrl, password });

  onProgress('Scanning for SEO basics...', 65);
  const seoResults = await c.action('scanner:checkSeo', { targetUrl, password });

  onProgress('Discovering API endpoints...', 80);
  const apiResults = await c.action('scanner:probeEndpoints', { targetUrl, password });

  onProgress('Checking information leakage...', 90);
  const leakResults = await c.action('scanner:checkLeakage', { targetUrl, password });

  onProgress('Compiling report...', 100);

  return {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    categories: {
      files: fileResults,
      headers: headerResults,
      robots: robotsResults,
      seo: seoResults,
      endpoints: apiResults,
      leakage: leakResults,
    },
  };
}
