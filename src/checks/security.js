const { readFileSafe, relativePath } = require('../utils');

const PATTERNS = [
  {
    name: 'Hardcoded API key',
    regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi,
    severity: 'critical',
    deduction: 8,
  },
  {
    name: 'Hardcoded token/secret',
    regex: /(?<![a-zA-Z])(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"](?![/.])[^'"]{8,}['"]/gi,
    severity: 'critical',
    deduction: 8,
  },
  {
    name: 'JWT literal',
    regex: /['"]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['"]/g,
    severity: 'critical',
    deduction: 10,
  },
  {
    name: 'dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML/g,
    severity: 'high',
    deduction: 5,
  },
  {
    name: 'innerHTML assignment (XSS risk)',
    regex: /\.innerHTML\s*=/g,
    severity: 'high',
    deduction: 5,
  },
  {
    name: 'document.write() usage',
    regex: /\bdocument\.write\s*\(/g,
    severity: 'high',
    deduction: 4,
  },
  {
    name: 'eval() usage',
    regex: /\beval\s*\(/g,
    severity: 'critical',
    deduction: 8,
  },
  {
    name: 'setTimeout/setInterval with string argument (implicit eval)',
    regex: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/g,
    severity: 'high',
    deduction: 6,
  },
  {
    name: 'Sensitive data in localStorage',
    regex: /localStorage\.setItem\s*\(\s*['"](?:token|auth|jwt|session|password|secret|api[_-]?key)/gi,
    severity: 'high',
    deduction: 5,
  },
  {
    name: 'Console.log of auth values',
    regex: /console\.log\s*\([^)]*(?:token|password|secret|jwt|auth|credential|apiKey)/gi,
    severity: 'high',
    deduction: 4,
  },
];

module.exports = async function securityCheck(files, dir) {
  const findings = [];
  const goodPractices = [];
  let totalDeduction = 0;

  for (const file of files) {
    const content = readFileSafe(file);
    const lines = content.split('\n');
    const rel = relativePath(file, dir);

    for (const pattern of PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(pattern.regex);
        if (matches) {
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

    // Good practice: uses environment variables
    if (content.match(/process\.env\./)) {
      goodPractices.push(`Uses environment variables (${rel})`);
    }
  }

  // Check for .env in .gitignore
  const { existsSync, readFileSync } = require('fs');
  const path = require('path');
  const gitignorePath = path.join(dir, '.gitignore');
  if (existsSync(gitignorePath)) {
    const gitignore = readFileSync(gitignorePath, 'utf-8');
    if (gitignore.includes('.env')) {
      goodPractices.push('.env is listed in .gitignore');
    }
  }

  const score = Math.max(0, 100 - totalDeduction);

  return {
    category: 'Security / Secrets',
    score,
    weight: 0.35,
    findings,
    goodPractices: [...new Set(goodPractices)],
    summary: findings.length === 0
      ? 'No hardcoded secrets or dangerous patterns detected'
      : `Found ${findings.length} security issue(s)`,
  };
};
