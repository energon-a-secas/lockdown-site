/**
 * Run: node --experimental-strip-types tests/guard.test.ts
 *
 * These exist to make the guard FAIL. A guard nobody has watched reject
 * something is an assumption, not a control.
 */
import { assertScannableUrl, assertScanSecret, ScanRejected } from "../convex/lib/guard.ts";

let pass = 0, fail = 0;

function rejects(label: string, fn: () => unknown) {
  try {
    fn();
    console.log(`  FAIL  ${label} — was ALLOWED but must be rejected`);
    fail++;
  } catch (e) {
    if (e instanceof ScanRejected) { console.log(`  ok    ${label}`); pass++; }
    else { console.log(`  FAIL  ${label} — wrong error: ${e}`); fail++; }
  }
}

function allows(label: string, fn: () => unknown) {
  try { fn(); console.log(`  ok    ${label}`); pass++; }
  catch (e) { console.log(`  FAIL  ${label} — was REJECTED: ${(e as Error).message}`); fail++; }
}

console.log("\nSSRF — private and reserved space must be refused");
rejects("loopback by name",        () => assertScannableUrl("http://localhost/"));
rejects("loopback 127.0.0.1",      () => assertScannableUrl("http://127.0.0.1:8080/"));
rejects("loopback 127.255.1.2",    () => assertScannableUrl("http://127.255.1.2/"));
rejects("RFC1918 10/8",            () => assertScannableUrl("http://10.1.2.3/"));
rejects("RFC1918 172.16/12",       () => assertScannableUrl("http://172.20.0.1/"));
rejects("RFC1918 192.168/16",      () => assertScannableUrl("https://192.168.1.1/admin"));
rejects("CLOUD METADATA 169.254",  () => assertScannableUrl("http://169.254.169.254/latest/meta-data/"));
rejects("CGNAT 100.64/10",         () => assertScannableUrl("http://100.100.0.1/"));
rejects("unspecified 0.0.0.0",     () => assertScannableUrl("http://0.0.0.0/"));
rejects("IPv6 loopback",           () => assertScannableUrl("http://[::1]/"));
rejects("IPv6 unique-local",       () => assertScannableUrl("http://[fd00::1]/"));
rejects("IPv6 link-local",         () => assertScannableUrl("http://[fe80::1]/"));
rejects("v4-mapped v6 loopback",   () => assertScannableUrl("http://[::ffff:127.0.0.1]/"));
rejects(".internal suffix",        () => assertScannableUrl("http://vault.internal/"));
rejects(".local suffix",           () => assertScannableUrl("http://nas.local/"));
rejects("file scheme",             () => assertScannableUrl("file:///etc/passwd"));
rejects("gopher scheme",           () => assertScannableUrl("gopher://evil/"));
rejects("not a URL",               () => assertScannableUrl("not a url"));

console.log("\nLegitimate public targets must still work");
allows("plain https",              () => assertScannableUrl("https://example.com/"));
allows("http with port",           () => assertScannableUrl("http://example.com:8080/x"));
allows("public IP literal",        () => assertScannableUrl("http://93.184.216.34/"));
allows("subdomain + path",         () => assertScannableUrl("https://a.b.example.co.uk/p?q=1"));

console.log("\nCredential — must fail closed");
rejects("secret unset on server",  () => assertScanSecret("anything", undefined));
rejects("secret unset, none sent", () => assertScanSecret(undefined, undefined));
rejects("wrong secret",            () => assertScanSecret("guess", "real"));
rejects("missing secret",          () => assertScanSecret(undefined, "real"));
allows("correct secret",           () => assertScanSecret("real", "real"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
