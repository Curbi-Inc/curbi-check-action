// Curbi Check: replay curbi.regression files against the Check API and report on the pull request.
// No dependencies. Reads inputs and writes outputs the way the Actions runner defines them (INPUT_*, GITHUB_OUTPUT,
// GITHUB_STEP_SUMMARY). Fails closed: a network error, a non-200 or an unreadable file fails the job, never passes it.
import { readFileSync, readdirSync, statSync, appendFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const MARKER = '<!-- curbi-check -->', BATCH = 50;
const input = (name, fallback = '') => (process.env['INPUT_' + name.replace(/ /g, '_').toUpperCase()] ?? fallback).trim() || fallback;
const out = (k, v) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
const md = s => String(s).replace(/[|`<>\r\n]/g, c => ({ '|': '\\|', '`': "'", '<': '&lt;', '>': '&gt;' })[c] ?? ' ');

export function findFiles(path) {
  if (!existsSync(path)) throw new Error(`No regressions at ${path}. Export one with export_regression or the Check page, and commit it there.`);
  if (statSync(path).isFile()) return [path];
  return readdirSync(path, { recursive: true }).map(f => join(path, String(f))).filter(f => f.endsWith('.json') && statSync(f).isFile()).sort();
}

export function load(file) {
  let s; try { s = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { throw new Error(`${file}: not JSON (${e.message})`); }
  if (s?.regression?.object === 'curbi.regression') s = s.regression;   // export_regression tool result, saved whole
  if (s?.object !== 'curbi.regression') return null;                   // other JSON in the folder is ignored
  if (!s.policy || !Array.isArray(s.cases) || !s.cases.length) throw new Error(`${file}: curbi.regression needs policy and cases`);
  for (const c of s.cases) if (typeof c.reply !== 'string' || typeof c.expectedPass !== 'boolean' || !Array.isArray(c.expectedRules)) throw new Error(`${file}: case ${c.id ?? '?'} needs reply, expectedPass and expectedRules`);
  return s;
}

async function check(api, key, suite, cases) {
  let r;
  try {
    r = await fetch(api, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(20000), headers: { 'Content-Type': 'application/json', 'User-Agent': 'curbi-check-action/1', ...(key ? { Authorization: 'Bearer ' + key } : {}) },
      body: JSON.stringify({ ...(suite.version ? { version: suite.version } : {}), policy: suite.policy, cases: cases.map(({ id, reply, record }) => ({ id, reply, ...(record ? { record } : {}) })) }) });
  } catch (e) { throw new Error(`Check API unreachable (${e.cause?.code ?? e.name}). No verdict was produced.`); }
  const body = await r.json().catch(() => null);
  if (r.status !== 200 || !Array.isArray(body?.results)) throw new Error(`Check API answered ${r.status}: ${body?.error?.message ?? 'no results'}. No verdict was produced.`);
  return body.results;
}

export async function run({ path, api, key }) {
  const rows = [];
  for (const file of findFiles(path)) {
    const suite = load(file); if (!suite) continue;
    for (let i = 0; i < suite.cases.length; i += BATCH) {
      const cases = suite.cases.slice(i, i + BATCH).map((c, j) => ({ ...c, id: String(c.id ?? i + j) })), results = await check(api, key, suite, cases);
      cases.forEach(c => {
        const r = results.find(x => x.id === c.id);
        const got = r ? [...new Set(r.findings.map(f => f.rule))].sort() : null, want = [...new Set(c.expectedRules)].sort();
        const ok = !!r && r.pass === c.expectedPass && JSON.stringify(got) === JSON.stringify(want);
        rows.push({ file, id: c.id, reply: c.reply, ok, want, got, findings: r?.findings ?? [] });
      });
    }
  }
  if (!rows.length) throw new Error(`No curbi.regression files found in ${path}.`);
  return rows;
}

export function report(rows, root = process.cwd()) {
  const failed = rows.filter(r => !r.ok), head = failed.length ? `❌ **Curbi Check: ${failed.length} of ${rows.length} cases changed**` : `✅ **Curbi Check: ${rows.length} cases match**`;
  const lines = [MARKER, head, '', '| | File | Case | Expected | Got |', '|---|---|---|---|---|'];
  for (const r of [...failed, ...rows.filter(r => r.ok)].slice(0, 100)) lines.push(`| ${r.ok ? '✅' : '❌'} | ${md(relative(root, r.file))} | ${md(r.id)} | ${md(r.want.join(', ') || 'pass')} | ${md(r.got ? r.got.join(', ') || 'pass' : 'missing')} |`);
  if (rows.length > 100) lines.push('', `Showing 100 of ${rows.length}.`);
  for (const r of failed.slice(0, 10)) {
    lines.push('', `<details><summary>${md(r.id)}: ${md(r.reply.slice(0, 80))}</summary>`, '');
    for (const f of r.findings) lines.push(`- \`${md(f.rule)}\` "${md(f.text)}": ${md(f.why)}`);
    if (!r.findings.length) lines.push('- No findings: the reply now passes.');
    lines.push('', '</details>');
  }
  lines.push('', 'A pass means no configured rule fired; it is not general truth and grants no permission. [Curbi](https://curbi.io/connect/)');
  return lines.join('\n');
}

async function comment(body, token) {
  const ev = process.env.GITHUB_EVENT_PATH && JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const pr = ev?.pull_request?.number; if (!pr || !token) return 'skipped (not a pull request)';
  const base = `${process.env.GITHUB_API_URL || 'https://api.github.com'}/repos/${process.env.GITHUB_REPOSITORY}/issues`;
  const gh = (url, method = 'GET', data) => fetch(url, { method, headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'curbi-check-action/1', 'Content-Type': 'application/json' }, body: data && JSON.stringify(data) });
  const list = await gh(`${base}/${pr}/comments?per_page=100`); if (!list.ok) return `skipped (${list.status})`;
  const mine = (await list.json()).find(c => c.body?.startsWith(MARKER));
  const r = mine ? await gh(`${base}/comments/${mine.id}`, 'PATCH', { body }) : await gh(`${base}/${pr}/comments`, 'POST', { body });
  return r.ok ? (mine ? 'updated' : 'posted') : `skipped (${r.status}; fork PRs and read-only tokens cannot comment)`;
}

export async function main() {
  try {
    const rows = await run({ path: input('path', 'curbi'), api: input('api', 'https://api.curbi.io/v1/check'), key: input('api-key') });
    const body = report(rows), failed = rows.filter(r => !r.ok).length;
    out('cases', rows.length); out('failed', failed);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, body + '\n');
    if (input('comment', 'true') === 'true') console.log('Comment:', await comment(body, input('github-token')));
    console.log(body);
    if (failed) { console.log(`::error::${failed} Curbi case(s) changed verdict or rules`); process.exitCode = 1; }
  } catch (e) { console.log(`::error::${e.message}`); process.exitCode = 1; }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
