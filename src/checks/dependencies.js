const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { readFileSafe, relativePath } = require('../utils');

function detectPackageManager(dir) {
  const lockfiles = [
    { file: 'bun.lockb', name: 'bun' },
    { file: 'bun.lock', name: 'bun' },
    { file: 'pnpm-lock.yaml', name: 'pnpm' },
    { file: 'package-lock.json', name: 'npm' },
  ];

  // Walk up from dir to filesystem root looking for a lockfile
  let current = path.resolve(dir);
  const root = path.parse(current).root;
  while (true) {
    for (const lf of lockfiles) {
      if (fs.existsSync(path.join(current, lf.file))) {
        return { name: lf.name, root: current };
      }
    }
    if (current === root) break;
    current = path.dirname(current);
  }

  return { name: 'npm', root: dir };
}

function parseBunAuditOutput(output) {
  // bun audit outputs plaintext with a summary like: "11 vulnerabilities (9 high, 2 moderate)"
  const summary = output.match(/(\d+)\s+vulnerabilit/);
  if (!summary) return null;

  const counts = { critical: 0, high: 0, moderate: 0 };
  const critMatch = output.match(/(\d+)\s+critical/);
  const highMatch = output.match(/(\d+)\s+high/);
  const modMatch = output.match(/(\d+)\s+moderate/);
  if (critMatch) counts.critical = parseInt(critMatch[1], 10);
  if (highMatch) counts.high = parseInt(highMatch[1], 10);
  if (modMatch) counts.moderate = parseInt(modMatch[1], 10);

  return counts;
}

function runAudit(pm) {
  const commands = {
    npm: 'npm audit --omit=dev --json 2>/dev/null',
    pnpm: 'pnpm audit --prod --json 2>/dev/null',
    bun: 'bun audit 2>/dev/null',
  };

  const cmd = commands[pm.name];
  let stdout = '';
  try {
    stdout = execSync(cmd, { cwd: pm.root, encoding: 'utf-8', timeout: 30000 });
  } catch (e) {
    // audit commands exit non-zero when vulnerabilities exist
    stdout = e.stdout || e.stderr || '';
  }

  if (!stdout.trim()) return null;

  // bun outputs plaintext, npm/pnpm output JSON
  if (pm.name === 'bun') {
    return parseBunAuditOutput(stdout);
  }

  // npm/pnpm JSON parsing
  try {
    const audit = JSON.parse(stdout);

    // npm v7+ format: { vulnerabilities: { pkg: { severity } } }
    if (audit.vulnerabilities && typeof audit.vulnerabilities === 'object' && !audit.metadata) {
      const counts = { critical: 0, high: 0, moderate: 0 };
      for (const v of Object.values(audit.vulnerabilities)) {
        const sev = v.severity || 'moderate';
        if (sev === 'critical') counts.critical++;
        else if (sev === 'high') counts.high++;
        else counts.moderate++;
      }
      return counts;
    }

    // npm v6 / metadata format
    if (audit.metadata && audit.metadata.vulnerabilities) {
      return {
        critical: audit.metadata.vulnerabilities.critical || 0,
        high: audit.metadata.vulnerabilities.high || 0,
        moderate: audit.metadata.vulnerabilities.moderate || 0,
      };
    }

    // pnpm format: { advisories: { id: { severity } } }
    if (audit.advisories) {
      const counts = { critical: 0, high: 0, moderate: 0 };
      for (const v of Object.values(audit.advisories)) {
        const sev = v.severity || 'moderate';
        if (sev === 'critical') counts.critical++;
        else if (sev === 'high') counts.high++;
        else counts.moderate++;
      }
      return counts;
    }
  } catch {}

  return null;
}

const RISKY_PACKAGES = [
  { name: 'node-serialize', severity: 'critical', deduction: 10, reason: 'Known RCE vulnerability' },
  { name: 'vm2', severity: 'high', deduction: 6, reason: 'Sandbox escape vulnerabilities' },
  { name: 'serialize-javascript', severity: 'medium', deduction: 3, reason: 'Potential prototype pollution' },
];

function checkLodashVersion(dir, pm) {
  // Only npm and pnpm have JSON-parseable lockfiles for this check
  if (pm.name === 'npm') {
    const lockPath = path.join(dir, 'package-lock.json');
    if (!fs.existsSync(lockPath)) return null;
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
      const deps = lock.dependencies || lock.packages || {};
      for (const [name, info] of Object.entries(deps)) {
        if (name === 'lodash' || name.endsWith('/lodash')) {
          const ver = info.version || '';
          const major = parseInt(ver.split('.')[0], 10);
          if (!isNaN(major) && major < 4) return ver;
        }
      }
    } catch {}
  }
  if (pm.name === 'pnpm') {
    // Check via pnpm list
    try {
      const out = execSync('pnpm list lodash --json 2>/dev/null', { cwd: dir, encoding: 'utf-8', timeout: 10000 });
      const parsed = JSON.parse(out);
      const list = Array.isArray(parsed) ? parsed : [parsed];
      for (const entry of list) {
        const deps = { ...entry.dependencies, ...entry.devDependencies };
        if (deps.lodash) {
          const major = parseInt(deps.lodash.version.split('.')[0], 10);
          if (!isNaN(major) && major < 4) return deps.lodash.version;
        }
      }
    } catch {}
  }
  return null;
}

function checkMoment(dir) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    return !!allDeps.moment;
  } catch {}
  return false;
}

module.exports = async function dependencyCheck(files, dir) {
  const findings = [];
  const goodPractices = [];
  let totalDeduction = 0;

  // Detect package manager and run audit
  const pkgPath = path.join(dir, 'package.json');
  const pm = detectPackageManager(dir);
  if (fs.existsSync(pkgPath)) {
    const auditCounts = runAudit(pm);
    if (auditCounts) {
      const { critical, high, moderate } = auditCounts;
      const total = critical + high + moderate;

      if (total > 0) {
        if (critical > 0) {
          const ded = Math.min(critical * 8, 30);
          totalDeduction += ded;
          findings.push({ file: 'package.json', line: null, message: `${pm.name} audit: ${critical} critical vulnerability(ies)`, severity: 'critical', deduction: ded });
        }
        if (high > 0) {
          const ded = Math.min(high * 4, 20);
          totalDeduction += ded;
          findings.push({ file: 'package.json', line: null, message: `${pm.name} audit: ${high} high vulnerability(ies)`, severity: 'high', deduction: ded });
        }
        if (moderate > 0) {
          const ded = Math.min(moderate * 2, 10);
          totalDeduction += ded;
          findings.push({ file: 'package.json', line: null, message: `${pm.name} audit: ${moderate} moderate/low vulnerability(ies)`, severity: 'medium', deduction: ded });
        }
      } else {
        goodPractices.push(`${pm.name} audit: no known vulnerabilities`);
      }
    }

    // Check risky packages
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const risky of RISKY_PACKAGES) {
        if (allDeps[risky.name]) {
          const ded = Math.min(risky.deduction, 100 - totalDeduction);
          totalDeduction += ded;
          findings.push({
            file: 'package.json',
            line: null,
            message: `Risky package: ${risky.name} — ${risky.reason}`,
            severity: risky.severity,
            deduction: ded,
          });
        }
      }
    } catch {}

    // Check lodash < v4
    const oldLodash = checkLodashVersion(dir, pm);
    if (oldLodash) {
      totalDeduction += 5;
      findings.push({
        file: 'package-lock.json',
        line: null,
        message: `lodash ${oldLodash} (< v4) has known vulnerabilities`,
        severity: 'high',
        deduction: 5,
      });
    }

    // Check moment.js
    if (checkMoment(dir)) {
      totalDeduction += 2;
      findings.push({
        file: 'package.json',
        line: null,
        message: 'moment.js is deprecated — consider date-fns or dayjs',
        severity: 'low',
        deduction: 2,
      });
    }
  }

  // Dynamic require with non-literal paths
  for (const file of files) {
    const content = readFileSafe(file);
    const lines = content.split('\n');
    const rel = relativePath(file, dir);

    for (let i = 0; i < lines.length; i++) {
      if (lines[i].match(/require\s*\(\s*[^'"`\s)]/)) {
        // require with a variable, not a literal string
        if (!lines[i].match(/require\s*\(\s*['"`]/)) {
          const ded = Math.min(4, 100 - totalDeduction);
          totalDeduction += ded;
          findings.push({
            file: rel,
            line: i + 1,
            message: 'Dynamic require() with non-literal path',
            severity: 'medium',
            deduction: ded,
          });
        }
      }
    }
  }

  const score = Math.max(0, 100 - totalDeduction);

  return {
    category: 'Dependency Vulnerabilities',
    score,
    weight: 0.20,
    findings,
    goodPractices,
    summary: findings.length === 0
      ? 'Dependencies look clean'
      : `Found ${findings.length} dependency concern(s)`,
  };
};
