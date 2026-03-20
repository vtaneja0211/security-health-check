const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', '.next', 'coverage', '.git',
]);

const SKIP_EXTENSIONS = new Set(['.d.ts']);

function shouldSkipFile(filePath) {
  const base = path.basename(filePath);
  if (base.includes('.test.') || base.includes('.spec.')) return true;
  if (filePath.endsWith('.d.ts')) return true;
  return false;
}

function isCodeFile(filePath) {
  const ext = path.extname(filePath);
  return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
}

function collectFiles(dir) {
  const results = [];

  function walk(current) {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && isCodeFile(fullPath) && !shouldSkipFile(fullPath)) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results;
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return '';
  }
}

function relativePath(filePath, dir) {
  return path.relative(dir || process.cwd(), filePath);
}

module.exports = { collectFiles, readFileSafe, relativePath, isCodeFile };
