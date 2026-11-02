// Security boundaries exercised without network sockets, credentials, or external services.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, load, report, main, LIMITS } from '../index.mjs';

// Fixtures live in a temporary directory even when the test runner itself is in GitHub Actions.
// Dedicated workspace-boundary tests below set their own isolated workspace and restore it.
const originalWorkspace = process.env.GITHUB_WORKSPACE;
before(() => { delete process.env.GITHUB_WORKSPACE; });
after(() => {
  if (originalWorkspace === undefined) delete process.env.GITHUB_WORKSPACE;
  else process.env.GITHUB_WORKSPACE = originalWorkspace;
});

const API = 'https://check.invalid/v1/check';
const regression = (cases, extra = {}) => ({
  object: 'curbi.regression', version: '2026-11-01', policy: {}, cases, ...extra,
});
const caseOf = (id, extra = {}) => ({ id, reply: 'A configured claim.', expectedPass: true, expectedRules: [], ...extra });
const response = results => new Response(JSON.stringify({ object: 'check.batch', results }), {
  status: 200, headers: { 'content-type': 'application/json' },
});
const passing = cases => cases.map(({ id }) => ({ id, pass: true, findings: [] }));

function fixture(t, suite = regression([caseOf('a')])) {
  const dir = mkdtempSync(join(tmpdir(), 'curbi-action-security-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'regression.json');
  writeFileSync(file, JSON.stringify(suite));
  return { dir, file };
}

async function withFetch(implementation, body) {
  const original = globalThis.fetch;
  globalThis.fetch = implementation;
  try { return await body(); } finally { globalThis.fetch = original; }
}

async function rejectsBeforeFetch(t, suite, pattern = /limit|large|size|bytes|duplicate|unique/i) {
  const { file } = fixture(t, suite);
  let calls = 0;
  await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
    await assert.rejects(run({ path: file, api: API }), pattern);
  });
  assert.equal(calls, 0, 'invalid local input must be rejected before a request');
}

test('request batches respect UTF-8 byte and case limits while preserving every case', async t => {
  const cases = Array.from({ length: 105 }, (_, i) => caseOf(`case-${i}`, {
    reply: '🛻'.repeat(700), record: { label: 'é'.repeat(100) },
  }));
  const policy = { context: 'é'.repeat(2000) };
  const { file } = fixture(t, regression(cases, { policy }));
  const batches = [];
  const rows = await withFetch(async (url, options) => {
    assert.equal(url, API);
    assert.equal(options.method, 'POST');
    assert.ok(Buffer.byteLength(options.body, 'utf8') <= 65_536, 'serialized request exceeds the API byte limit');
    const body = JSON.parse(options.body);
    assert.ok(body.cases.length <= 50, 'serialized request exceeds the API case limit');
    assert.deepEqual(body.policy, policy);
    assert.equal(body.version, '2026-11-01');
    batches.push(body.cases);
    return response(passing(body.cases));
  }, () => run({ path: file, api: API }));
  assert.ok(batches.length > Math.ceil(cases.length / 50), 'UTF-8 size must split batches before the 50-case cap');
  assert.deepEqual(batches.flat().map(c => c.id), cases.map(c => c.id));
  assert.equal(rows.length, cases.length);
  assert.ok(rows.every(row => row.ok));
});

test('invalid and insecure remote endpoints reject before any request', async t => {
  const { file } = fixture(t);
  for (const api of [
    'not a URL', '/v1/check', 'http://check.invalid/v1/check', 'ftp://check.invalid/v1/check',
    'https://user:password@check.invalid/v1/check', 'https://check.invalid/v1/check#fragment',
  ]) {
    await t.test(api, async () => {
      let calls = 0;
      await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
        await assert.rejects(run({ path: file, api, key: 'test-credential' }), /endpoint|https/i);
      });
      assert.equal(calls, 0, 'unsafe endpoint must not receive a credential or fixture');
    });
  }
});

test('an oversized policy or single case fails before a request', async t => {
  await t.test('policy overhead', st => rejectsBeforeFetch(st, regression([caseOf('a')], {
    policy: { context: 'p'.repeat(LIMITS.requestBytes) },
  })));
  await t.test('single case', st => rejectsBeforeFetch(st, regression([
    caseOf('a', { record: { context: '🛻'.repeat(Math.ceil(LIMITS.requestBytes / 4)) } }),
  ])));
});

test('case IDs reject non-strings and duplicate generated or explicit IDs', async t => {
  const variants = [
    [caseOf('a'), caseOf('a')],
    [caseOf(undefined), caseOf('0')],
  ];
  for (const [index, cases] of variants.entries()) {
    await t.test(`collision ${index + 1}`, st => rejectsBeforeFetch(st, regression(cases), /duplicate|unique/i));
  }
  await t.test('numeric ID cannot collide with a string ID after coercion', st =>
    rejectsBeforeFetch(st, regression([caseOf(1), caseOf('1')]), /id|identifier/i));
});

test('malformed API results fail closed instead of producing regression rows', async t => {
  const a = { id: 'a', pass: true, findings: [] };
  const b = { id: 'b', pass: true, findings: [] };
  const variants = {
    'missing result': [a],
    'extra result': [a, b, { ...a, id: 'c' }],
    'unexpected ID at the same cardinality': [a, { ...b, id: 'unexpected' }],
    'duplicate response ID': [a, a],
    'non-string response ID': [{ ...a, id: 0 }, b],
    'non-boolean pass': [{ ...a, pass: 'true' }, b],
    'missing pass': [{ id: 'a', findings: [] }, b],
    'missing findings': [{ id: 'a', pass: true }, b],
    'non-array findings': [{ ...a, findings: {} }, b],
    'null finding': [{ ...a, pass: false, findings: [null] }, b],
    'non-string rule': [{ ...a, pass: false, findings: [{ rule: 1, text: 'x', why: 'x' }] }, b],
    'non-string text': [{ ...a, pass: false, findings: [{ rule: 'forbid:x', text: {}, why: 'x' }] }, b],
    'non-string why': [{ ...a, pass: false, findings: [{ rule: 'forbid:x', text: 'x', why: [] }] }, b],
    'passing verdict with findings': [{ ...a, findings: [{ rule: 'forbid:x', text: 'x', why: 'x' }] }, b],
    'failing verdict without findings': [{ ...a, pass: false }, b],
  };
  for (const [name, results] of Object.entries(variants)) {
    await t.test(name, async st => {
      const { file } = fixture(st, regression([caseOf('a'), caseOf('b')]));
      await withFetch(async () => response(results), async () => {
        await assert.rejects(run({ path: file, api: API }), /response|result|verdict|schema|findings|invalid|malformed/i);
      });
    });
  }
  await t.test('missing batch envelope', async st => {
    const { file } = fixture(st, regression([caseOf('a'), caseOf('b')]));
    await withFetch(async () => new Response(JSON.stringify({ results: [a, b] }), { status: 200 }), async () => {
      await assert.rejects(run({ path: file, api: API }), /response|result|verdict|batch|invalid|malformed/i);
    });
  });
});

test('the response byte limit applies even when Content-Length is absent or false', async t => {
  const { file } = fixture(t);
  for (const advertisedLength of [undefined, '1']) {
    await t.test(advertisedLength ? 'false Content-Length' : 'missing Content-Length', async () => {
      const body = JSON.stringify({ object: 'check.batch', results: passing([{ id: 'a' }]), padding: 'p'.repeat(LIMITS.responseBytes) });
      await withFetch(async () => new Response(body, { status: 200, headers: advertisedLength ? { 'content-length': advertisedLength } : {} }), async () => {
        await assert.rejects(run({ path: file, api: API }), /large|limit|bytes|size/i);
      });
    });
  }
});

test('untrusted report fields cannot inject Markdown, HTML, extra rows, or terminal controls', () => {
  const hostile = '![click](https://evil.invalid) **bold** _italic_ <img src=x> | new\nrow\r\u001b[31m';
  const text = report([{
    file: `/workspace/${hostile}.json`, id: hostile, reply: hostile,
    ok: false, want: [hostile], got: [hostile],
    findings: [{ rule: hostile, text: hostile, why: hostile }],
  }], '/workspace');
  assert.doesNotMatch(text, /<img|\u001b|\r/);
  assert.doesNotMatch(text, /(?<!\\)!?\[click\]\(https:\/\/evil\.invalid\)/);
  assert.doesNotMatch(text, /(?<!\\)\*\*bold\*\*|(?<!\\)_italic_/);
  assert.equal(text.split('\n').filter(line => line.startsWith('|')).length, 3, 'untrusted newlines must not create additional table rows');
  assert.equal(text.split('\n').filter(line => line.startsWith('<details>')).length, 1);
});

test('large reports stay bounded and preserve the complete verdict counts', () => {
  const rows = Array.from({ length: 125 }, (_, i) => ({
    file: `/workspace/regression-${i}.json`, id: `case-${i}`, reply: 'A changed reply.',
    ok: false, want: [], got: ['forbid:x'],
    findings: [{ rule: 'forbid:x', text: 'x', why: 'w'.repeat(8000) }],
  }));
  const text = report(rows, '/workspace');
  assert.ok(text.length <= LIMITS.reportChars, 'report exceeds the GitHub comment limit');
  assert.match(text, /125 of 125 cases changed/);
  assert.match(text, /truncated/i);
  assert.equal(text.split('\n').filter(line => line.startsWith('<details>')).length,
    text.split('\n').filter(line => line === '</details>').length, 'truncation must preserve complete details blocks');
});

test('symlink inputs and oversized files are rejected before reading or sending them', async t => {
  await t.test('symlink file', async st => {
    const { dir, file } = fixture(st);
    const link = join(dir, 'linked.json');
    symlinkSync(file, link);
    let calls = 0;
    await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: link, api: API }), /symbolic|symlink|link/i);
    });
    assert.equal(calls, 0);
  });
  await t.test('symlink directory', async st => {
    const { dir } = fixture(st);
    const link = join(dir, 'linked-directory');
    symlinkSync(dir, link, 'dir');
    await withFetch(async () => { throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: link, api: API }), /symbolic|symlink|link/i);
    });
  });
  await t.test('file bytes', async st => {
    const { file } = fixture(st);
    writeFileSync(file, ' '.repeat(LIMITS.fileBytes + 1));
    assert.throws(() => load(file), /large|limit|bytes|size/i);
  });
});

test('GitHub workspace boundaries reject outside paths and symlink ancestors before any request', async t => {
  await t.test('a regular nested fixture inside the workspace remains usable', async st => {
    const { dir } = fixture(st);
    const nested = join(dir, 'nested');
    mkdirSync(nested);
    const file = join(nested, 'regression.json');
    writeFileSync(file, JSON.stringify(regression([caseOf('a')])));
    const previous = process.env.GITHUB_WORKSPACE;
    process.env.GITHUB_WORKSPACE = dir;
    try {
      const rows = await withFetch(async (_url, options) => response(passing(JSON.parse(options.body).cases)),
        () => run({ path: file, api: API }));
      assert.equal(rows.length, 1);
      assert.equal(rows[0].ok, true);
    } finally {
      if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
      else process.env.GITHUB_WORKSPACE = previous;
    }
  });
  await t.test('outside the workspace, including a same-prefix sibling', async st => {
    const { dir, file } = fixture(st);
    const workspace = join(dir, 'workspace');
    const sibling = join(dir, 'workspace-escape');
    mkdirSync(workspace); mkdirSync(sibling);
    const siblingFile = join(sibling, 'regression.json');
    writeFileSync(siblingFile, JSON.stringify(regression([caseOf('a')])));
    const previous = process.env.GITHUB_WORKSPACE;
    process.env.GITHUB_WORKSPACE = workspace;
    try {
      for (const path of [file, siblingFile]) {
        let calls = 0;
        await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
          await assert.rejects(run({ path, api: API }), /workspace|outside|within|contain|boundary/i);
        });
        assert.equal(calls, 0, 'an outside-workspace fixture must not be sent');
      }
    } finally {
      if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
      else process.env.GITHUB_WORKSPACE = previous;
    }
  });
  await t.test('a regular file reached through a symlink directory', async st => {
    const { dir, file } = fixture(st);
    const workspace = join(dir, 'workspace');
    mkdirSync(workspace);
    symlinkSync(dir, join(workspace, 'nested'), 'dir');
    const path = join(workspace, 'nested', 'regression.json');
    assert.equal(readFileSync(path, 'utf8'), readFileSync(file, 'utf8'), 'the fixture is readable through the link');
    const previous = process.env.GITHUB_WORKSPACE;
    process.env.GITHUB_WORKSPACE = workspace;
    let calls = 0;
    try {
      await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
        await assert.rejects(run({ path, api: API }), /symlink|symbolic|workspace|outside/i);
      });
      assert.equal(calls, 0, 'a symlink ancestor must be rejected before reading a verdict');
    } finally {
      if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
      else process.env.GITHUB_WORKSPACE = previous;
    }
  });
});

test('directory walking and total regression cases have explicit resource bounds', async t => {
  await t.test('JSON file count', async st => {
    const { dir } = fixture(st);
    for (let i = 0; i < LIMITS.files; i++) writeFileSync(join(dir, `other-${i}.json`), '{}');
    await withFetch(async () => { throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: dir, api: API }), /files|limit/i);
    });
  });
  await t.test('all directory entries count, including non-JSON files', async st => {
    const { dir } = fixture(st);
    for (let i = 0; i < LIMITS.entries; i++) writeFileSync(join(dir, `other-${i}.txt`), '');
    await withFetch(async () => { throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: dir, api: API }), /entries|limit/i);
    });
  });
  await t.test('directory depth', async st => {
    const { dir } = fixture(st);
    let nested = dir;
    for (let i = 0; i <= LIMITS.depth; i++) { nested = join(nested, 'nested'); mkdirSync(nested); }
    writeFileSync(join(nested, 'deep.json'), '{}');
    await withFetch(async () => { throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: dir, api: API }), /depth|deep|limit/i);
    });
  });
  await t.test('total cases', async st => {
    const { dir, file } = fixture(st);
    const cases = Array.from({ length: Math.ceil(LIMITS.cases / 2) + 1 }, (_, i) => caseOf(String(i), { reply: 'x' }));
    writeFileSync(file, JSON.stringify(regression(cases)));
    writeFileSync(join(dir, 'second.json'), JSON.stringify(regression(cases)));
    let calls = 0;
    await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: dir, api: API }), /cases|limit/i);
    });
    assert.equal(calls, 0, 'all local cases should be counted before the first request');
  });
  await t.test('aggregate file bytes', async st => {
    const { dir, file } = fixture(st);
    const content = Buffer.alloc(LIMITS.fileBytes, ' ');
    content.write(JSON.stringify(regression([caseOf('a')])));
    writeFileSync(file, content);
    for (let i = 1; i <= Math.floor(LIMITS.totalFileBytes / LIMITS.fileBytes); i++) {
      writeFileSync(join(dir, `padded-${i}.json`), content);
    }
    let calls = 0;
    await withFetch(async () => { calls++; throw new Error('unexpected request'); }, async () => {
      await assert.rejects(run({ path: dir, api: API }), /aggregate.*size|total.*bytes|limit/i);
    });
    assert.equal(calls, 0, 'aggregate fixture bytes must be checked before any request');
  });
});

async function optionalComment(t, failComment, expectedComments = 1) {
  const { dir, file } = fixture(t);
  const event = join(dir, 'event.json'), output = join(dir, 'output'), summary = join(dir, 'summary');
  writeFileSync(event, JSON.stringify({ pull_request: { number: 7 } }));
  writeFileSync(output, ''); writeFileSync(summary, '');
  const overrides = {
    INPUT_PATH: file, INPUT_API: API, INPUT_COMMENT: 'true', 'INPUT_API-KEY': '',
    'INPUT_GITHUB-TOKEN': 'test-token', GITHUB_EVENT_PATH: event,
    GITHUB_API_URL: 'https://github.invalid', GITHUB_REPOSITORY: 'owner/repository',
    GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary,
  };
  const previous = Object.fromEntries(Object.keys(overrides).map(key => [key, process.env[key]]));
  const oldExitCode = process.exitCode;
  Object.assign(process.env, overrides); process.exitCode = undefined;
  const messages = [];
  const originalLog = console.log;
  console.log = (...args) => messages.push(args.join(' '));
  let comments = 0;
  try {
    await withFetch(async (url, options) => {
      if (url === API) return response(passing(JSON.parse(options.body).cases));
      comments++;
      return failComment(url, options);
    }, () => main());
    assert.equal(comments, expectedComments, 'the optional comment path should actually be attempted');
    assert.equal(process.exitCode ?? 0, 0, messages.join('\n'));
    assert.match(readFileSync(output, 'utf8'), /cases=1\nfailed=0\n/);
    assert.match(readFileSync(summary, 'utf8'), /1 cases match/);
    assert.doesNotMatch(messages.join('\n'), /::error::/);
  } finally {
    console.log = originalLog;
    process.exitCode = oldExitCode;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
}

test('optional PR comment transport rejection does not fail passing checks', async t => {
  await optionalComment(t, async () => { throw new TypeError('connection reset'); });
});

test('a human comment with the report marker is never patched', async t => {
  const requests = [];
  await optionalComment(t, async (url, options) => {
    requests.push({ url, method: options.method });
    if (options.method === 'GET') return new Response(JSON.stringify([
      { id: 123, body: '<!-- curbi-check -->\nHuman-authored comment', user: { login: 'human', type: 'User' } },
      { id: 124, body: '<!-- curbi-check -->\nSpoofed login', user: { login: 'github-actions[bot]', type: 'User' } },
    ]), { status: 200 });
    return new Response('{}', { status: 201 });
  }, 2);
  assert.deepEqual(requests.map(request => request.method), ['GET', 'POST']);
  assert.ok(requests[1].url.endsWith('/issues/7/comments'), 'a new bot report should be posted to the PR');
});

test('optional PR comment timeout is bounded and does not fail passing checks', async t => {
  const originalTimeout = AbortSignal.timeout.bind(AbortSignal);
  t.mock.method(AbortSignal, 'timeout', () => originalTimeout(5));
  let observedSignal = false, aborted = false;
  await optionalComment(t, async (_url, options) => {
    observedSignal = !!options.signal;
    if (!options.signal) throw new Error('GitHub requests need a timeout signal');
    return new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('comment request was never aborted')), 250);
      options.signal.addEventListener('abort', () => { aborted = true; clearTimeout(timer); reject(options.signal.reason); }, { once: true });
    });
  });
  assert.ok(observedSignal, 'the optional comment transport received a timeout signal');
  assert.ok(aborted, 'the optional comment transport was actually aborted');
});
