const { readFileSafe, relativePath } = require('../utils');

const PATTERNS = [
  {
    name: 'Hardcoded isAdmin flag',
    regex: /\bisAdmin\s*[:=]\s*(?:true|false)\b/g,
    severity: 'critical',
    deduction: 8,
  },
  {
    name: 'Client-side role check',
    regex: /(?:role|userRole)\s*===?\s*['"](?:admin|superadmin|moderator)['"]/gi,
    severity: 'high',
    deduction: 5,
  },
  {
    name: 'Auth state from localStorage',
    regex: /localStorage\.getItem\s*\(\s*['"](?:token|auth|jwt|user|session|isAuthenticated|isAdmin)/gi,
    severity: 'high',
    deduction: 4,
  },
];

module.exports = async function authCheck(files, dir) {
  const findings = [];
  const goodPractices = [];
  let totalDeduction = 0;

  let hasPrivateRoute = false;
  let hasRequireAuth = false;
  let hasAuthProvider = false;
  let hasSupabaseAuth = false;
  let hasErrorBoundary = false;

  for (const file of files) {
    const content = readFileSafe(file);
    const lines = content.split('\n');
    const rel = relativePath(file, dir);

    // Check good practices
    if (content.match(/PrivateRoute|ProtectedRoute/)) hasPrivateRoute = true;
    if (content.match(/RequireAuth|AuthGuard|withAuth/)) hasRequireAuth = true;
    if (content.match(/AuthProvider|AuthContext/)) hasAuthProvider = true;
    if (content.match(/supabase\.auth|useSupabaseClient|@supabase\/auth/)) hasSupabaseAuth = true;
    if (content.match(/ErrorBoundary|componentDidCatch|error\s*boundary/i)) hasErrorBoundary = true;

    for (const pattern of PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].match(pattern.regex)) {
          const deduction = Math.min(pattern.deduction, 100 - totalDeduction);
          totalDeduction += deduction;
          findings.push({
            file: rel,
            line: i + 1,
            message: pattern.name,
            severity: pattern.severity,
            deduction,
          });
        }
      }
    }

    // jwt.decode without jwt.verify — skips signature validation
    if (content.match(/\bjwt\.decode\s*\(/) && !content.match(/\bjwt\.verify\s*\(/)) {
      const deduction = Math.min(8, 100 - totalDeduction);
      totalDeduction += deduction;
      findings.push({
        file: rel,
        line: null,
        message: 'jwt.decode() used without jwt.verify() — token signature not validated',
        severity: 'critical',
        deduction,
      });
    }

    // Check for unprotected route definitions (Route without auth wrapper)
    const routeMatches = content.match(/<Route\s[^>]*path\s*=\s*['"][^'"]*['"]/g);
    if (routeMatches && !content.match(/PrivateRoute|ProtectedRoute|RequireAuth|AuthGuard/)) {
      if (content.match(/(?:dashboard|admin|settings|profile|account)/i)) {
        const deduction = Math.min(5, 100 - totalDeduction);
        totalDeduction += deduction;
        findings.push({
          file: rel,
          line: null,
          message: 'Sensitive routes without auth wrapper',
          severity: 'high',
          deduction,
        });
      }
    }
  }

  if (hasPrivateRoute) goodPractices.push('Uses PrivateRoute/ProtectedRoute pattern');
  if (hasRequireAuth) goodPractices.push('Uses RequireAuth/AuthGuard pattern');
  if (hasAuthProvider) goodPractices.push('Uses AuthProvider/AuthContext');
  if (hasSupabaseAuth) goodPractices.push('Uses Supabase auth');
  if (hasErrorBoundary) goodPractices.push('Has error boundaries');

  const score = Math.max(0, 100 - totalDeduction);

  return {
    category: 'Auth Patterns',
    score,
    weight: 0.25,
    findings,
    goodPractices,
    summary: findings.length === 0
      ? 'Auth patterns look solid'
      : `Found ${findings.length} auth concern(s)`,
  };
};
