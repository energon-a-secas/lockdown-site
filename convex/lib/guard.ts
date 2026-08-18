/**
 * Request guards for the scanner actions.
 *
 * The scanner fetches arbitrary user-supplied URLs from Convex's network.
 * Without these checks the actions are an open proxy: anyone holding the
 * public deployment URL can aim them at a third party, or at infrastructure
 * only reachable from inside the runtime.
 *
 * Everything here is a pure function so it can be tested without a
 * deployment. See tests/guard.test.ts.
 */

export class ScanRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanRejected";
  }
}

/** Hostnames that never denote a legitimate public scan target. */
const BLOCKED_HOST_SUFFIXES = [
  "localhost",
  ".localhost",
  ".internal",
  ".local",
  ".home.arpa",
];

/** IPv4 CIDRs that must never be reachable through the scanner. */
const BLOCKED_V4: Array<[string, number]> = [
  ["0.0.0.0", 8],      // "this host"
  ["10.0.0.0", 8],     // RFC1918
  ["100.64.0.0", 10],  // CGNAT
  ["127.0.0.0", 8],    // loopback
  ["169.254.0.0", 16], // link-local — cloud instance metadata lives here
  ["172.16.0.0", 12],  // RFC1918
  ["192.0.0.0", 24],   // IETF protocol assignments
  ["192.168.0.0", 16], // RFC1918
  ["198.18.0.0", 15],  // benchmarking
  ["224.0.0.0", 4],    // multicast
  ["240.0.0.0", 4],    // reserved
];

function v4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = (out << 8) + n;
  }
  return out >>> 0;
}

function inV4Cidr(ip: number, base: string, bits: number): boolean {
  const b = v4ToInt(base);
  if (b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (b & mask);
}

/** True for any IPv6 literal we refuse to reach. */
function isBlockedV6(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "::" || h === "::1") return true;          // unspecified, loopback
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;        // fc00::/7 unique-local
  if (/^fe[89ab][0-9a-f]:/.test(h)) return true;        // fe80::/10 link-local
  if (h.startsWith("::ffff:")) {
    // v4-mapped. The URL parser normalizes ::ffff:127.0.0.1 to the hex form
    // ::ffff:7f00:1, so both spellings have to be handled here.
    const mapped = h.slice(7);
    if (mapped.includes(".")) return isBlockedV4Literal(mapped);
    const groups = mapped.split(":");
    if (groups.length !== 2) return false;
    const hi = parseInt(groups[0], 16);
    const lo = parseInt(groups[1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) return false;
    const asV4 = [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join(".");
    return isBlockedV4Literal(asV4);
  }
  return false;
}

function isBlockedV4Literal(host: string): boolean {
  const ip = v4ToInt(host);
  if (ip === null) return false;
  return BLOCKED_V4.some(([base, bits]) => inV4Cidr(ip, base, bits));
}

/**
 * Validate a scan target and return it normalized.
 * Throws ScanRejected with a reason the UI can show verbatim.
 */
export function assertScannableUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanRejected("Target is not a valid URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanRejected(`Unsupported scheme "${url.protocol}" — only http and https are scannable.`);
  }

  const host = url.hostname.toLowerCase();
  if (!host) throw new ScanRejected("Target has no hostname.");

  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host === suffix || host.endsWith(suffix)) {
      throw new ScanRejected(`Refusing to scan internal hostname "${host}".`);
    }
  }
  if (isBlockedV4Literal(host) || isBlockedV6(host)) {
    throw new ScanRejected(`Refusing to scan private or reserved address "${host}".`);
  }

  return url;
}

/**
 * Validate the caller's shared secret against the deployment's.
 *
 * Fails closed: if SCAN_SECRET is unset on the deployment, every call is
 * refused rather than silently allowing all of them. A guard that defaults
 * to "allow" when misconfigured is not a guard.
 */
export function assertScanSecret(provided: string | undefined, expected: string | undefined): void {
  if (!expected) {
    throw new ScanRejected("Scanner is not configured: SCAN_SECRET is unset on the deployment.");
  }
  if (!provided || provided !== expected) {
    throw new ScanRejected("Invalid or missing scan credential.");
  }
}
