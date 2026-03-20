const { readFileSafe, relativePath } = require('../utils');

const PATTERNS = [
  {
    name: 'Empty catch block',
    regex: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    severity: 'medium',
    deduction: 3,
  },
  {
    name: 'Comment-only catch block',
    regex: /catch\s*\([^)]*\)\s*\{\s*\/\/[^\n]*\s*\}/g,
    severity: 'medium',
    deduction: 2,
  },
  {
    name: '@ts-ignore directive',
    regex: /@ts-ignore/g,
    severity: 'medium',
    deduction: 2,
  },
  {
    name: '@ts-nocheck directive',
    regex: /@ts-nocheck/g,
    severity: 'high',
    deduction: 5,
  },
  {
    name: 'Unimplemented stub',
    regex: /throw\s+new\s+Error\s*\(\s*['"]Not implemented['"]\s*\)/g,
    severity: 'medium',
    deduction: 3,
  },
  {
    name: 'debugger statement',
    regex: /\bdebugger\b/g,
    severity: 'medium',
    deduction: 3,
  },
  {
    name: 'Promise.all without .catch',
    regex: /Promise\.all\s*\([^)]*\)(?!\s*\.catch)(?!\s*\.\s*then\s*\([^)]*\)\s*\.catch)/g,
    severity: 'low',
    deduction: 2,
  },
];

module.exports = async function codeQualityCheck(files, dir) {
  const findings = [];
  const goodPractices = [];
  let totalDeduction = 0;

  for (const file of files) {
    const content = readFileSafe(file);
    const lines = content.split('\n');
    const rel = relativePath(file, dir);

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
  }

  const score = Math.max(0, 100 - totalDeduction);

  return {
    category: 'Code Quality / Hygiene',
    score,
    weight: 0.10,
    findings,
    goodPractices,
    summary: findings.length === 0
      ? 'Code quality looks good'
      : `Found ${findings.length} code quality issue(s)`,
  };
};
