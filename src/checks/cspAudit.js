const fs = require('fs');
const path = require('path');

// Extract CSP string from index.html meta tag
function parseCsp(html) {
  // Match content="..." or content='...' separately so inner single-quotes aren't stripped
  const dq = html.match(/<meta\s+http-equiv=["']Content-Security-Policy["'][^>]+content="([^"]+)"/i);
  if (dq) return dq[1];
  const sq = html.match(/<meta\s+http-equiv=["']Content-Security-Policy["'][^>]+content='([^']+)'/i);
  return sq ? sq[1] : null;
}

// Parse CSP string into { directive -> [sources] }
function parseCspDirectives(csp) {
  const directives = {};
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length === 0 || !tokens[0]) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

// Extract hostname from a URL string (strips path/query/wildcard)
function hostname(url) {
  try {
    const u = new URL(url.replace(/\*/g, 'wildcard'));
    return u.hostname.replace('wildcard.', '*.').replace('.wildcard', '');
  } catch {
    return null;
  }
}

// Does `origin` match a CSP source like https://example.com or https://*.example.com ?
function matchesCspSource(origin, sources) {
  let h;
  try {
    h = new URL(origin).hostname;
  } catch {
    return false;
  }
  for (const src of sources) {
    if (src === "'self'" || src === '*') return true;
    try {
      const srcHost = new URL(src.replace(/\*/g, 'wildcard')).hostname;
      if (srcHost === h) return true;
      // wildcard subdomain match: *.example.com matches foo.example.com
      if (srcHost.startsWith('wildcard.')) {
        const base = srcHost.slice('wildcard.'.length);
        if (h === base || h.endsWith('.' + base)) return true;
      }
    } catch {
      // bare keyword like 'unsafe-inline'
    }
  }
  return false;
}

// Pull every explicit external URL from src/href/action attributes in the HTML
function extractResourceUrls(html) {
  const resources = [];
  // <script src="...">
  for (const m of html.matchAll(/<script[^>]+\bsrc=["']([^"']+)["']/gi)) {
    resources.push({ type: 'script-src', url: m[1] });
  }
  // <link href="...">
  for (const m of html.matchAll(/<link[^>]+\bhref=["']([^"']+)["']/gi)) {
    resources.push({ type: 'style-src', url: m[1] });
  }
  // <iframe src="...">
  for (const m of html.matchAll(/<iframe[^>]+\bsrc=["']([^"']+)["']/gi)) {
    resources.push({ type: 'frame-src', url: m[1] });
  }
  return resources.filter(r => /^https?:\/\//i.test(r.url));
}

// Maps npm package name patterns to the external CDN domains they call out to at runtime.
// Add entries here as new third-party packages are integrated.
const PACKAGE_CDN_MAP = [
  // Unlayer email editor — loads editor JS + assets from its own CDN
  { pkg: /react-email-editor|@unlayer\//,    domains: ['unlayer.com'] },
  // PostHog — calls back to posthog.com (also usually in source but belt+suspenders)
  { pkg: /posthog/,                          domains: ['posthog.com'] },
  // Google reCAPTCHA (loaded dynamically, not an npm package, but gstatic is its dep)
  // Covered by checking 'recaptcha' or 'google.com/recaptcha' in source files.
  // gstatic.com is loaded transitively by google.com/recaptcha/api.js
  { pkg: /recaptcha/,                        domains: ['gstatic.com'] },
  // Google Tag Manager / Analytics — googletagmanager.com already in index.html
  // but gstatic.com is also used by GTM/GA tags
  { pkg: /gtm|google.*tag|analytics/,        domains: ['gstatic.com'] },
  // Firebase
  { pkg: /firebase/,                         domains: ['gstatic.com', 'googleapis.com'] },
  // Tiptap YouTube extension
  { pkg: /@tiptap\/.*youtube|tiptap-youtube/, domains: ['youtube.com', 'youtu.be'] },
  // Mermaid diagrams
  { pkg: /mermaid/,                          domains: ['cdn.jsdelivr.net'] },
];

// Maps a keyword found in source (or CSP resources) to domains it transitively loads.
// E.g. google.com/recaptcha loads additional scripts from gstatic.com at runtime.
// More specific entries must come before broader ones (find() returns first match).
const TRANSITIVE_DOMAIN_MAP = [
  // Google Fonts stylesheet (fonts.googleapis.com) serves font files from fonts.gstatic.com
  { sourceKeyword: 'fonts.googleapis.com', domains: ['fonts.gstatic.com'] },
  // reCAPTCHA JS (loaded from google.com) pulls sub-resources from gstatic.com
  { sourceKeyword: 'recaptcha',            domains: ['gstatic.com'] },
  // Google Tag Manager can also load from gstatic
  { sourceKeyword: 'googletagmanager',     domains: ['gstatic.com'] },
  // Firebase JS SDK loads from gstatic.com
  { sourceKeyword: 'firebase',             domains: ['gstatic.com'] },
];

// Return whether a CSP source is a plain keyword (not a URL)
const KEYWORDS = new Set([
  "'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'", "'strict-dynamic'",
  "'report-sample'", "'wasm-unsafe-eval'", 'data:', 'blob:', 'https:', 'http:',
]);

module.exports = async function cspAuditCheck(files, dir) {
  const findings = [];
  const goodPractices = [];
  let totalDeduction = 0;

  const indexPath = fs.existsSync(path.join(dir, 'index.html'))
    ? path.join(dir, 'index.html')
    : path.join(dir, 'public', 'index.html');
  if (!fs.existsSync(indexPath)) {
    return {
      category: 'CSP Audit',
      score: 100,
      weight: 0.1,
      findings: [],
      goodPractices: [],
      summary: 'No index.html found — skipped',
    };
  }

  const html = fs.readFileSync(indexPath, 'utf-8');
  const cspString = parseCsp(html);

  if (!cspString) {
    findings.push({
      file: 'index.html',
      line: null,
      message: 'No Content-Security-Policy meta tag found',
      severity: 'high',
      deduction: 10,
    });
    totalDeduction += 10;
    return {
      category: 'CSP Audit',
      score: Math.max(0, 100 - totalDeduction),
      weight: 0.1,
      findings,
      goodPractices,
      summary: 'CSP meta tag missing',
    };
  }

  goodPractices.push('Content-Security-Policy meta tag present in index.html');

  const directives = parseCspDirectives(cspString);
  const resources = extractResourceUrls(html);

  // ── 1. Dangerous directives ──────────────────────────────────────────────
  const DANGEROUS = [
    { keyword: "'unsafe-inline'", directive: 'script-src', label: "script-src contains 'unsafe-inline'", deduction: 5 },
    { keyword: "'unsafe-eval'",   directive: 'script-src', label: "script-src contains 'unsafe-eval'",   deduction: 5 },
    { keyword: "'unsafe-inline'", directive: 'style-src',  label: "style-src contains 'unsafe-inline'",  deduction: 3 },
  ];
  for (const d of DANGEROUS) {
    const sources = directives[d.directive] || directives['default-src'] || [];
    if (sources.includes(d.keyword)) {
      findings.push({
        file: 'index.html',
        line: null,
        message: d.label,
        severity: 'medium',
        deduction: d.deduction,
        audit: true,
      });
      totalDeduction += d.deduction;
    }
  }

  // ── 2. Resources in index.html blocked by CSP ────────────────────────────
  for (const res of resources) {
    const applicable = [res.type, 'default-src'];
    const sources = applicable.flatMap(d => directives[d] || []);
    if (!matchesCspSource(res.url, sources)) {
      findings.push({
        file: 'index.html',
        line: null,
        message: `Resource not covered by CSP (would be blocked): ${res.url}`,
        severity: 'high',
        deduction: 4,
        audit: true,
      });
      totalDeduction += 4;
    }
  }

  // ── 3. CSP domains not in index.html — search source + packages to classify ──
  const { readFileSafe } = require('../utils');
  const sourceBlob = files.map(f => readFileSafe(f)).join('\n');

  // Load installed package names from package.json
  let installedPackages = [];
  const pkgJsonPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      installedPackages = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    } catch { /* ignore */ }
  }

  // Extract the searchable domain string from a CSP src like https://*.posthog.com
  function searchDomain(src) {
    try {
      const host = new URL(src.replace(/\*/g, 'x')).hostname;
      return host.replace(/^x\./, '');
    } catch {
      return null;
    }
  }

  // Find which installed package explains a domain (via PACKAGE_CDN_MAP)
  function explainedByPackage(domain) {
    for (const entry of PACKAGE_CDN_MAP) {
      const matchingPkg = installedPackages.find(p => entry.pkg.test(p));
      if (matchingPkg && entry.domains.some(d => domain.endsWith(d) || d.endsWith(domain))) {
        return matchingPkg;
      }
    }
    return null;
  }

  const AUDITABLE_DIRECTIVES = ['script-src', 'style-src', 'font-src', 'frame-src'];
  const staleSrcs = [];

  for (const dir_ of AUDITABLE_DIRECTIVES) {
    const sources = directives[dir_] || [];
    for (const src of sources) {
      if (KEYWORDS.has(src)) continue;

      // Skip if already covered by an explicit resource in index.html
      const inHtml = resources.some(r => {
        if (dir_ === 'frame-src' && r.type !== 'frame-src') return false;
        if (dir_ === 'script-src' && r.type !== 'script-src') return false;
        if (dir_ === 'style-src' && r.type !== 'style-src') return false;
        if (dir_ === 'font-src') return false;
        return matchesCspSource(r.url, [src]);
      });
      if (inHtml) continue;

      const domain = searchDomain(src);

      // 1. Referenced directly in source code
      if (domain && sourceBlob.includes(domain)) {
        goodPractices.push(`${dir_}: ${src} — referenced in source (dynamic load)`);
        continue;
      }

      // 2. Explained by a known npm package
      const pkg = domain && explainedByPackage(domain);
      if (pkg) {
        goodPractices.push(`${dir_}: ${src} — loaded by npm package "${pkg}"`);
        continue;
      }

      // 3. Explained by a transitive relationship — e.g. loading recaptcha pulls gstatic.com
      const transitiveEntry = domain && TRANSITIVE_DOMAIN_MAP.find(
        e => e.domains.some(d => domain.endsWith(d) || d.endsWith(domain))
           && (sourceBlob.includes(e.sourceKeyword) || html.includes(e.sourceKeyword))
      );
      if (transitiveEntry) {
        goodPractices.push(`${dir_}: ${src} — loaded transitively (via "${transitiveEntry.sourceKeyword}")`);
        continue;
      }

      // 4. No evidence anywhere — flag as stale
      staleSrcs.push(src);
      findings.push({
        file: 'index.html',
        line: null,
        message: `${dir_}: ${src} — no usage found in codebase or known packages, likely stale`,
        severity: 'low',
        deduction: 2,
        audit: true,
      });
      totalDeduction += 2;
    }
  }

  const score = Math.max(0, 100 - totalDeduction);
  const blockers = findings.filter(f => f.severity === 'high').length;
  const dangers = findings.filter(f => f.severity === 'medium').length;
  const staleCount = staleSrcs.length;

  return {
    category: 'CSP Audit',
    score,
    weight: 0.1,
    findings,
    goodPractices,
    summary: [
      blockers && `${blockers} blocked resource(s)`,
      dangers && `${dangers} dangerous directive(s)`,
      staleCount && `${staleCount} stale CSP entr${staleCount === 1 ? 'y' : 'ies'} to remove`,
      !findings.length && 'CSP looks clean',
    ].filter(Boolean).join(', '),
  };
};
