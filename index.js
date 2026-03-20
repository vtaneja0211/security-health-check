#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const minimist = require('minimist');
const chalk = require('chalk');

const securityCheck = require('./src/checks/security');
const authCheck = require('./src/checks/auth');
const dependencyCheck = require('./src/checks/dependencies');
const codeQualityCheck = require('./src/checks/codeQuality');
const cspAuditCheck = require('./src/checks/cspAudit');
const { collectFiles } = require('./src/utils');

const argv = minimist(process.argv.slice(2), {
  string: ['dir', 'json'],
  boolean: ['no-fail', 'help'],
  default: { dir: '.', threshold: 70, 'no-fail': false },
});

if (argv.help) {
  console.log(`
${chalk.bold('security-health-check')} — scan a codebase for AI-generated code issues

${chalk.bold('Usage:')}
  security-health-check [options]

${chalk.bold('Options:')}
  --dir <path>       Root directory to scan (default: .)
  --threshold <n>    Minimum passing score 0-100 (default: 70)
  --json <path>      Write JSON report to file
  --no-fail          Exit 0 regardless of score
  --help             Show this help
`);
  process.exit(0);
}

async function main() {
  const dir = path.resolve(argv.dir);
  const threshold = Number(argv.threshold);

  if (!fs.existsSync(dir)) {
    console.error(chalk.red(`Directory not found: ${dir}`));
    process.exit(1);
  }

  console.log(chalk.bold('\n  security-health-check\n'));
  console.log(chalk.gray(`  Scanning: ${dir}`));
  console.log(chalk.gray(`  Threshold: ${threshold}\n`));

  const files = collectFiles(dir);
  console.log(chalk.gray(`  Files found: ${files.length}\n`));

  const checks = [securityCheck, authCheck, dependencyCheck, codeQualityCheck, cspAuditCheck];
  const results = [];

  for (const check of checks) {
    const result = await check(files, dir);
    results.push(result);
  }

  const overallScore = Math.round(
    results.reduce((sum, r) => sum + r.score * r.weight, 0)
  );
  const passed = overallScore >= threshold;

  // Print score card
  console.log(chalk.bold('  ─── Score Card ───────────────────────────────────\n'));

  const scoreColor = passed ? chalk.green : chalk.red;
  console.log(
    `  Overall Score: ${scoreColor.bold(overallScore + '/100')}  ${passed ? chalk.green('PASS') : chalk.red('FAIL')} (threshold: ${threshold})\n`
  );

  // Per-category
  for (const r of results) {
    const catScore = Math.round(r.score * 100) / 100;
    const weighted = Math.round(r.score * r.weight * 100) / 100;
    const barLen = Math.round(catScore / 5);
    const bar = chalk.green('█'.repeat(barLen)) + chalk.gray('░'.repeat(20 - barLen));
    console.log(`  ${bar}  ${chalk.bold(r.category)} — ${catScore}/100 (×${r.weight} = ${weighted})`);
    console.log(chalk.gray(`  ${r.summary}\n`));
  }

  // Findings grouped by file
  const findingsByFile = {};
  for (const r of results) {
    for (const f of r.findings) {
      const key = f.file || 'project';
      if (!findingsByFile[key]) findingsByFile[key] = [];
      findingsByFile[key].push({ ...f, category: r.category });
    }
  }

  const fileKeys = Object.keys(findingsByFile);
  if (fileKeys.length > 0) {
    console.log(chalk.bold('  ─── Findings ─────────────────────────────────────\n'));
    for (const file of fileKeys) {
      console.log(chalk.underline(`  ${file}`));
      for (const f of findingsByFile[file]) {
        const sevColor =
          f.severity === 'critical' ? chalk.red :
          f.severity === 'high' ? chalk.yellow :
          f.severity === 'medium' ? chalk.cyan :
          chalk.gray;
        const line = f.line ? `:${f.line}` : '';
        console.log(`    ${sevColor(`[${f.severity}]`)} ${f.message}${chalk.gray(line)} ${chalk.gray(`(-${f.deduction}pts)`)}`);
      }
      console.log();
    }
  }

  // Good practices
  const allGood = results.flatMap(r => r.goodPractices);
  if (allGood.length > 0) {
    console.log(chalk.bold('  ─── Good Practices ───────────────────────────────\n'));
    for (const g of allGood) {
      console.log(chalk.green(`  ✓ ${g}`));
    }
    console.log();
  }

  console.log(chalk.bold('  ─────────────────────────────────────────────────\n'));

  // JSON report
  if (argv.json) {
    const report = {
      score: overallScore,
      threshold,
      passed,
      scanDir: dir,
      filesScanned: files.length,
      categories: results.map(r => ({
        category: r.category,
        score: r.score,
        weight: r.weight,
        weighted: Math.round(r.score * r.weight * 100) / 100,
        summary: r.summary,
        findings: r.findings,
        goodPractices: r.goodPractices,
      })),
    };
    fs.writeFileSync(argv.json, JSON.stringify(report, null, 2));
    console.log(chalk.gray(`  Report written to ${argv.json}\n`));
  }

  if (!passed && !argv['no-fail']) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error(chalk.red(err.message));
  process.exit(1);
});
