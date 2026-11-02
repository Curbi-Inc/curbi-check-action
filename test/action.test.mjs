// The Action against a fake Check API and a fake GitHub API: no network, no token.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { run, report, load } from '../index.mjs';

const originalWorkspace=process.env.GITHUB_WORKSPACE;
delete process.env.GITHUB_WORKSPACE;
after(()=>{if(originalWorkspace!==undefined)process.env.GITHUB_WORKSPACE=originalWorkspace;});

let api, gh, apiUrl, ghUrl, status = 200; const seen = [], comments = [];
const listen = (h) => new Promise(r => { const s = createServer(h).listen(0, '127.0.0.1', () => r(s)); });
before(async () => {
  api = await listen((req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => {
    const body = JSON.parse(b); seen.push({ auth: req.headers.authorization, body });
    // Fake checker: "$29" is a price mismatch, anything else passes.
    const results = body.cases.map(c => /\$29/.test(c.reply) ? { id: c.id, pass: false, findings: [{ rule: 'price:mismatch', text: '$29', why: 'Pro is $49, not $29.' }] } : { id: c.id, pass: true, findings: [] });
    res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(status === 200 ? { object: 'check.batch', results } : { error: { message: 'rate limited' } }));
  }); });
  gh = await listen((req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => {
    if (req.method === 'GET') { res.writeHead(200); return res.end(JSON.stringify(comments)); }
    const body = JSON.parse(b).body; if (req.method === 'PATCH') comments[0].body = body; else comments.push({ id: 7, body, method: req.method, user: { login: 'github-actions[bot]', type: 'Bot' } });
    res.writeHead(req.method === 'POST' ? 201 : 200); res.end('{}');
  }); });
  apiUrl = `http://127.0.0.1:${api.address().port}/v1/check`; ghUrl = `http://127.0.0.1:${gh.address().port}`;
});
after(() => { api.close(); gh.close(); });

const suite = (cases, extra = {}) => ({ object: 'curbi.regression', version: '2026-11-01', policy: { prices: [{ item: 'Pro', amount: 49 }] }, cases, ...extra });
const dir = files => { const d = mkdtempSync(join(tmpdir(), 'cca-')); mkdirSync(join(d, 'curbi')); for (const [n, c] of Object.entries(files)) writeFileSync(join(d, 'curbi', n), typeof c === 'string' ? c : JSON.stringify(c)); return d; };
const OK = suite([{ id: 'wrong', reply: 'Pro is $29.', expectedPass: false, expectedRules: ['price:mismatch'] }, { id: 'right', reply: 'Pro is $49.', expectedPass: true, expectedRules: [] }]);

test('matching regressions pass; API key is sent as Bearer', async () => {
  const rows = await run({ path: join(dir({ 'a.json': OK }), 'curbi'), api: apiUrl, key: 'ck_live_x' });
  assert.deepEqual(rows.map(r => r.ok), [true, true]); assert.equal(seen.at(-1).auth, 'Bearer ck_live_x');
});
test('a changed verdict fails, in either direction', async () => {
  const flipped = suite([{ id: 'now-passes', reply: 'Pro is $49.', expectedPass: false, expectedRules: ['price:mismatch'] }, { id: 'now-fails', reply: 'Pro is $29.', expectedPass: true, expectedRules: [] }]);
  const rows = await run({ path: join(dir({ 'b.json': flipped }), 'curbi'), api: apiUrl });
  assert.deepEqual(rows.map(r => r.ok), [false, false]); assert.match(report(rows), /❌ \*\*Curbi Check: 2 of 2 cases changed/);
});
test('export_regression tool results are accepted whole; unrelated JSON is ignored; >50 cases are batched', async () => {
  const many = suite(Array.from({ length: 120 }, (_, i) => ({ reply: i % 2 ? 'Pro is $29.' : 'Pro is $49.', expectedPass: !(i % 2), expectedRules: i % 2 ? ['price:mismatch'] : [] })));
  const n = seen.length, rows = await run({ path: join(dir({ 'tool.json': { regression: OK }, 'package.json': { name: 'x' }, 'many.json': many }), 'curbi'), api: apiUrl });
  assert.equal(rows.length, 122); assert.ok(rows.every(r => r.ok)); assert.equal(seen.length - n, 4, '1 + 3 batches');
});
test('fails closed: non-200, unreachable API, bad JSON, missing folder, empty folder', async () => {
  status = 429; await assert.rejects(run({ path: join(dir({ 'a.json': OK }), 'curbi'), api: apiUrl }), /429/); status = 200;
  await assert.rejects(run({ path: join(dir({ 'a.json': OK }), 'curbi'), api: 'http://127.0.0.1:1/v1/check' }), /unreachable/);
  await assert.rejects(run({ path: join(dir({ 'a.json': '{nope' }), 'curbi'), api: apiUrl }), /not JSON/);
  await assert.rejects(run({ path: '/nonexistent/curbi', api: apiUrl }), /Cannot read regression path/);
  await assert.rejects(run({ path: join(dir({ 'x.json': { a: 1 } }), 'curbi'), api: apiUrl }), /No curbi.regression files/);
  assert.throws(() => load(join(dir({ 'a.json': suite([{ reply: 'x' }]) }), 'curbi', 'a.json')), /needs reply, expectedPass and expectedRules/);
});
test('report escapes hostile replies (no markup, no table breaks)', () => {
  const r = report([{ file: 'curbi/a.json', id: 'x|y', reply: '<img src=x onerror=alert(1)>', ok: false, want: [], got: ['forbid:x'], findings: [{ rule: 'forbid:x', text: '<b>|`', why: 'w' }] }], '.');
  assert.doesNotMatch(r, /<img|<b>/); assert.match(r, /x&#124;y/);
});
const child = env => new Promise(r => { let stdout = '', stderr = ''; const p = spawn(process.execPath, [new URL('../index.mjs', import.meta.url).pathname], { env });
  p.stdout.on('data', d => stdout += d); p.stderr.on('data', d => stderr += d); p.on('close', status => r({ status, stdout, stderr })); });
test('end to end as the runner calls it: summary, outputs, one PR comment updated in place, exit code', async () => {
  const d = dir({ 'a.json': OK }), f = n => join(d, n); writeFileSync(f('event.json'), JSON.stringify({ pull_request: { number: 5 } })); writeFileSync(f('out'), ''); writeFileSync(f('sum'), '');
  const env = { ...process.env, GITHUB_WORKSPACE:d, INPUT_PATH: join(d, 'curbi'), INPUT_API: apiUrl, INPUT_COMMENT: 'true', 'INPUT_GITHUB-TOKEN': 't', GITHUB_EVENT_PATH: f('event.json'), GITHUB_API_URL: ghUrl, GITHUB_REPOSITORY: 'o/r', GITHUB_OUTPUT: f('out'), GITHUB_STEP_SUMMARY: f('sum') };
  const a = await child(env);
  assert.equal(a.status, 0, a.stdout + a.stderr); assert.match(readFileSync(f('out'), 'utf8'), /cases=2\nfailed=0/); assert.match(readFileSync(f('sum'), 'utf8'), /✅ \*\*Curbi Check: 2 cases match/);
  assert.equal(comments.length, 1); assert.match(a.stdout, /Comment: posted/);
  writeFileSync(join(d, 'curbi', 'a.json'), JSON.stringify(suite([{ id: 'w', reply: 'Pro is $29.', expectedPass: true, expectedRules: [] }])));
  const b = await child(env);
  assert.equal(b.status, 1); assert.match(b.stdout, /Comment: updated/); assert.equal(comments.length, 1); assert.match(comments[0].body, /1 of 1 cases changed/); assert.match(b.stdout, /::error::1 Curbi case/);
});
