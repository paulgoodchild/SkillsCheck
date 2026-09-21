import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { scan, configure } from '../skillcheck/scan.mjs';

const helper = fileURLToPath(new URL('../skillcheck/scan.mjs', import.meta.url));
const ids = ['injection', 'exfiltration', 'network', 'filesystem', 'execution', 'concealment', 'boundaries', 'purpose'];
const secret = 'dummy-local-key';
const marker = 'TARGET_CONTROLLED_MARKER';
const answers = (value = 0.01) => ({ answers: Object.fromEntries(ids.map(id => [id, { type: 'noul', noul: value }])) });
const reply = value => new Response(JSON.stringify(value), { status: 200 });

async function fixture(t) {
  const home = await mkdtemp(join(tmpdir(), 'skillcheck-test-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const root = join(home, 'target'), config = join(home, 'config'), key = join(config, 'jev-api-key');
  await mkdir(root);
  await mkdir(config);
  await writeFile(key, secret);
  await writeFile(join(root, 'SKILL.md'), '# Example\nAn inert test skill.');
  return { home, root, key };
}

function capture(body = answers()) {
  const requests = [];
  return { requests, send: async (url, options) => { requests.push({ url, ...options }); return reply(body); } };
}

test('real collection and serialization preserve text; only fixed scores escape', async t => {
  const { root, key } = await fixture(t);
  const text = '# '+marker+'\nUnicode: café 日本語; "quotes" \\ slash\n';
  await writeFile(join(root, '.hidden'), text);
  await writeFile(join(root, marker + '.png'), text);
  await writeFile(join(root, 'script'), 'throw new Error("never execute");');
  const transport = capture({ ...answers(), model: marker, extra: marker });
  const result = await scan(join(root, 'SKILL.md'), key, transport.send);
  assert.equal(result.status, 'PASS');
  assert.equal(result.coverage_complete, true);
  assert.deepEqual(Object.keys(result), ['status', 'code', 'scores', 'coverage_complete', 'batches']);
  assert.deepEqual(Object.keys(result.scores), ids);
  const [request] = transport.requests;
  assert.equal(request.url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(request.headers.Authorization, `Bearer ${secret}`);
  assert.equal(request.redirect, 'error');
  assert.ok(request.signal instanceof AbortSignal);
  const body = JSON.parse(request.body);
  assert.equal(body.model, 'jev-latest');
  assert.deepEqual(Object.keys(body.questions), ids);
  assert.ok(Object.values(body.questions).every(q => q.type === 'noul'));
  assert.ok(Object.values(body.questions).every(q => typeof q.instructions === 'string' && !q.instructions.includes('[object Object]')));
  for (const id of ['network', 'filesystem', 'execution', 'purpose']) {
    assert.deepEqual(Object.keys(body.questions[id].criteria).sort(), ['false', 'true']);
    assert.ok(Object.values(body.questions[id].criteria).every(value => typeof value === 'string' && value.length > 0));
  }
  assert.equal(body.state.files.find(f => f.path === marker + '.png').text, text);
  assert.equal(body.state.files.find(f => f.path === '.hidden').text, text);
  assert.equal(body.state.files.length, 4);
  assert.ok(!JSON.stringify(result).includes(marker));
  assert.ok(!request.body.includes(secret));
});

test('binary media is omitted without adding requests, even above the batch target', async t => {
  for (const size of [20 * 1024, 100 * 1024, 1024 * 1024]) {
    const { root, key } = await fixture(t);
    await writeFile(join(root, 'logo.png'), Buffer.alloc(size));
    await writeFile(join(root, 'instructions.md'), 'a'.repeat(10 * 1024));
    const transport = capture();
    const result = await scan(root, key, transport.send);
    assert.equal(result.status, 'PASS', `binary media size ${size}`);
    assert.equal(transport.requests.length, 1);
    assert.equal(JSON.parse(transport.requests[0].body).state.files.length, 2);
  }
});

test('oversized media text is scanned whole; a later binary marker is omitted', async t => {
  const { root, key } = await fixture(t);
  // A probe ending within a valid multibyte character must not classify text as binary.
  for (const content of ['é'.repeat(140 * 1024), 'a'.repeat(270 * 1024) + '\0']) {
    await writeFile(join(root, 'payload.png'), content);
    const transport = capture();
    assert.equal((await scan(root, key, transport.send)).status, 'PASS');
    const files = transport.requests.flatMap(r => JSON.parse(r.body).state.files);
    assert.equal(files.find(f => f.path === 'payload.png')?.text, content.includes('\0') ? undefined : content);
    assert.equal(transport.requests.length, content.includes('\0') ? 1 : 2);
  }
});

test('binary media and VCS exempt; dependencies and unsupported files prevent PASS', async t => {
  const { root, key } = await fixture(t);
  await writeFile(join(root, 'icon.PNG'), Buffer.from([0, 255, 10]));
  await mkdir(join(root, '.git'));
  await writeFile(join(root, '.git', 'ignored'), marker);
  assert.equal((await scan(root, key, capture().send)).status, 'PASS');
  for (const directory of ['node_modules', 'vendor', '.venv', 'venv', '__pycache__', '.cache']) {
    await mkdir(join(root, directory));
    await writeFile(join(root, directory, 'payload.sh'), marker);
    const transport = capture();
    const result = await scan(root, key, transport.send);
    assert.equal(result.status, 'WARN');
    assert.equal(result.coverage_complete, false);
    assert.ok(!transport.requests[0].body.includes(marker));
    await rm(join(root, directory), { recursive: true });
  }
  for (const [name, data] of [['bad.txt', Buffer.from([255])], ['archive.zip', Buffer.from([0, 1])]]) {
    await writeFile(join(root, name), data);
    assert.equal((await scan(root, key, capture().send)).status, 'WARN');
    assert.equal((await scan(root, key, capture(answers(0.95)).send)).status, 'FAIL');
    await rm(join(root, name));
  }
});

test('BOM accepted, invalid SKILL.md and missing targets never submit', async t => {
  const { root, key } = await fixture(t);
  await writeFile(join(root, 'SKILL.md'), '\ufeff# Example');
  const good = capture();
  assert.equal((await scan(root, key, good.send)).status, 'PASS');
  assert.equal(JSON.parse(good.requests[0].body).state.files[0].text, '# Example');
  for (const content of [Buffer.from([255]), Buffer.from([0])]) {
    await writeFile(join(root, 'SKILL.md'), content);
    const bad = capture();
    assert.equal((await scan(root, key, bad.send)).code, 'invalid_target');
    assert.equal(bad.requests.length, 0);
  }
  await rm(join(root, 'SKILL.md'));
  const missing = capture();
  assert.equal((await scan(root, key, missing.send)).code, 'invalid_target');
  assert.equal((await scan(root + '-absent', key, missing.send)).code, 'invalid_target');
  assert.equal(missing.requests.length, 0);
});

test('nested symlinks/junctions never submit external data; selected root link works', async t => {
  const { home, root, key } = await fixture(t);
  const outside = join(home, 'outside');
  await mkdir(outside);
  await writeFile(join(outside, 'canary.txt'), marker);
  const linkType = process.platform === 'win32' ? 'junction' : 'dir';
  await symlink(outside, join(root, 'nested-link'), linkType);
  const transport = capture();
  assert.equal((await scan(root, key, transport.send)).coverage_complete, false);
  assert.ok(!transport.requests[0].body.includes(marker));
  const rootLink = join(home, 'selected-root');
  await symlink(root, rootLink, linkType);
  assert.equal((await scan(rootLink, key, capture().send)).code, 'partial_scan');
  await rm(join(root, 'nested-link'));
  if (process.platform !== 'win32') {
    await symlink(join(outside, 'absent'), join(root, 'dangling'));
    assert.equal((await scan(root, key, capture().send)).status, 'WARN');
    await rm(join(root, 'dangling'));
    await rm(join(root, 'SKILL.md'));
    await symlink(join(outside, 'canary.txt'), join(root, 'SKILL.md'));
    assert.equal((await scan(root, key, capture().send)).code, 'invalid_target');
  }
});

test('48 KiB skills and oversized singleton text reach Jev', async t => {
  const { root, key } = await fixture(t);
  for (const size of [49175, 200 * 1024]) {
    await writeFile(join(root, 'SKILL.md'), 'a'.repeat(size));
    const transport = capture();
    assert.equal((await scan(root, key, transport.send)).status, 'PASS');
    assert.equal(transport.requests.length, 1);
    assert.equal(JSON.parse(transport.requests[0].body).state.files[0].text.length, size);
  }
  // Local acceptance does not imply the provider's token limit will accept it.
  assert.equal((await scan(root, key, async () => new Response(marker, { status: 413 }))).batches[0].code, 'request_failed');
});

test('entry bounds prevent all requests, including deep trees', async t => {
  for (const kind of ['entries', 'deep']) {
    const { root, key } = await fixture(t);
    if (kind === 'entries') {
      for (let i = 0; i < 256; i++) await writeFile(join(root, String(i)), '');
    } else {
      let path = root;
      for (let i = 0; i < 256; i++) { path = join(path, 'd'); await mkdir(path); }
    }
    const transport = capture();
    const result = await scan(root, key, transport.send);
    assert.deepEqual(result, { status: 'WARN', code: 'limit_exceeded', scores: null, coverage_complete: false });
    assert.equal(transport.requests.length, 0);
  }
});

test('verdict boundaries and invalid answer structures', async t => {
  const { root, key } = await fixture(t);
  for (const [score, status] of [[0, 'PASS'], [0.199999, 'PASS'], [0.20, 'WARN'], [0.899999, 'WARN'], [0.90, 'FAIL'], [1, 'FAIL']]) {
    assert.equal((await scan(root, key, capture(answers(score)).send)).status, status);
  }
  const invalid = [null, {}, { answers: [] }, { answers: null }];
  const missing = answers(); delete missing.answers.injection; invalid.push(missing);
  const extra = answers(); extra.answers[marker] = { type: 'noul', noul: 0 }; invalid.push(extra);
  for (const value of ['0.1', true, null, -1, 1.01, {}, []]) {
    const body = answers(); body.answers.injection.noul = value; invalid.push(body);
  }
  for (const answer of [null, [], { type: 'choice', noul: 0.1 }, { noul: 0.1 }]) {
    const body = answers(); body.answers.injection = answer; invalid.push(body);
  }
  for (const body of invalid) {
    const result = await scan(root, key, capture(body).send);
    assert.equal(result.batches[0].code, 'invalid_response');
    assert.equal(result.scores, null);
  }
  for (const raw of ['<html>'+marker, '{bad json', '{"answers":{"injection":{"type":"noul","noul":NaN}}}', 'x'.repeat(65537)]) {
    assert.equal((await scan(root, key, async () => new Response(raw))).batches[0].code, 'invalid_response');
  }
});

test('authentication versus other failures: fixed errors and no reflected bodies', async t => {
  const { root, key } = await fixture(t);
  for (const status of [401, 403, 400, 429, 500]) {
    const result = await scan(root, key, async () => new Response(marker, { status }));
    assert.equal(result.batches[0].code, [401, 403].includes(status) ? 'authentication_failed' : 'request_failed');
    assert.equal(result.scores, null);
    assert.equal(result.batches[0].http_status, status);
    assert.ok(!JSON.stringify(result).includes(marker));
  }
  for (const error of [new Error(marker), new DOMException(marker, 'TimeoutError')]) {
    const result = await scan(root, key, async () => { throw error; });
    assert.equal(result.batches[0].code, 'request_failed');
    assert.equal(result.batches[0].http_status, null);
    assert.equal(result.batches[0].reason, error.name === 'TimeoutError' ? 'timeout' : 'network_error');
  }
});

test('common HTTP failures return only fixed diagnostics, including bounded nested errors', async t => {
  const { root, key } = await fixture(t);
  const cases = [
    [400, { detail: { error_type: 'TokensExceeded', note: marker } }, 'context_limit_exceeded'],
    [422, { error: { message: 'Maximum token count exceeded: ' + marker } }, 'context_limit_exceeded'],
    [400, { detail: 'Request too large: ' + marker }, 'request_too_large'],
    [400, { detail: { message: 'Invalid field', input: 'context length exceeded' } }, 'request_rejected'],
    [422, { message: marker }, 'request_rejected'],
    [402, marker, 'payment_required'], [408, marker, 'timeout'],
    [413, marker, 'request_too_large'], [429, marker, 'rate_limited'],
    [500, marker, 'service_error'], [503, marker, 'service_error'], [504, marker, 'timeout'],
  ];
  for (const [status, body, reason] of cases) {
    const result = await scan(root, key, async () => new Response(JSON.stringify(body), { status }));
    assert.equal(result.batches[0].code, 'request_failed');
    assert.equal(result.batches[0].http_status, status);
    assert.equal(result.batches[0].reason, reason);
    assert.equal(result.scores, null);
    assert.ok(!JSON.stringify(result).includes(marker));
  }
  for (const raw of ['<html>' + marker, 'x'.repeat(65537)]) {
    const result = await scan(root, key, async () => new Response(raw, { status: 400 }));
    assert.equal(result.batches[0].reason, 'request_rejected');
    assert.equal(result.batches[0].http_status, 400);
  }
  const stream = new ReadableStream({ start(controller) { controller.error(new DOMException(marker, 'TimeoutError')); } });
  const timedOut = await scan(root, key, async () => new Response(stream));
  assert.equal(timedOut.batches[0].code, 'request_failed');
  assert.equal(timedOut.batches[0].reason, 'timeout');
  assert.equal(timedOut.batches[0].http_status, 200);
  assert.ok(!JSON.stringify(timedOut).includes(marker));
});

test('configuration is reused, missing key never requests, contained or linked key rejected', async t => {
  const { home, root, key } = await fixture(t);
  const transport = capture();
  const before = (await lstat(key)).mtimeMs;
  await scan(root, key, transport.send);
  assert.equal((await lstat(key)).mtimeMs, before);
  const missing = capture();
  assert.equal((await scan(root, join(home, 'missing', 'key'), missing.send)).code, 'configuration_required');
  assert.equal(missing.requests.length, 0);
  await writeFile(join(home, 'SKILL.md'), 'example');
  assert.equal((await scan(home, key, missing.send)).code, 'invalid_target');
  const link = join(home, 'linked-config');
  await symlink(join(home, 'config'), link, process.platform === 'win32' ? 'junction' : 'dir');
  assert.equal((await scan(root, join(link, 'jev-api-key'), missing.send)).code, 'configuration_required');
});

function terminal() {
  const input = new PassThrough();
  input.isTTY = true; input.isRaw = false;
  input.setRawMode = raw => { input.isRaw = raw; };
  let text = '';
  const output = new Writable({ write(chunk, encoding, callback) { text += chunk; callback(); } });
  output.isTTY = true;
  return { input, output, text: () => text };
}

test('terminal configure hides key, restores input, and stores private POSIX modes', async t => {
  const { home } = await fixture(t);
  const key = join(home, 'fresh', 'jev-api-key');
  const tty = terminal();
  const running = configure(key, tty.input, tty.output);
  tty.input.write(secret + '\r');
  await running;
  assert.equal(await readFile(key, 'utf8'), secret);
  assert.equal(tty.input.isRaw, false);
  assert.ok(!tty.text().includes(secret));
  if (process.platform !== 'win32') {
    assert.equal((await lstat(key)).mode & 0o777, 0o600);
    assert.equal((await lstat(join(home, 'fresh'))).mode & 0o777, 0o700);
  }
  const cancelled = terminal();
  const pending = configure(key, cancelled.input, cancelled.output);
  cancelled.input.write('discarded\x03');
  await assert.rejects(pending);
  assert.equal(cancelled.input.isRaw, false);
  assert.equal(await readFile(key, 'utf8'), secret);
  const nonTty = terminal(); nonTty.input.isTTY = false;
  await assert.rejects(configure(key, nonTty.input, nonTty.output));
});

test('unreadable file prevents PASS on non-root Unix', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, async t => {
  const { root, key } = await fixture(t);
  const file = join(root, 'restricted');
  await writeFile(file, marker);
  await chmod(file, 0o000);
  try { assert.equal((await scan(root, key, capture().send)).status, 'WARN'); }
  finally { await chmod(file, 0o600); }
});

test('CLI emits fixed JSON with correct exit codes and no stderr or injected text', async t => {
  const { home, root } = await fixture(t);
  const env = { ...process.env, LOCALAPPDATA: home, XDG_CONFIG_HOME: home };
  const config = join(home, 'skillcheck'); await mkdir(config);
  await writeFile(join(config, 'jev-api-key'), secret);
  for (const [score, status, code] of [[0.01, 'PASS', 0], [0.20, 'WARN', 1], [0.90, 'FAIL', 2]]) {
    const stub = join(home, 'fetch-stub.mjs');
    await writeFile(stub, `globalThis.fetch = async () => new Response(${JSON.stringify(JSON.stringify(answers(score)))});`);
    const run = spawnSync(process.execPath, ['--import', pathToFileURL(stub).href, helper, root], { env, encoding: 'utf8' });
    assert.equal(run.status, code, run.stderr);
    assert.equal(run.stderr, '');
    assert.equal(JSON.parse(run.stdout).status, status);
    assert.ok(!run.stdout.includes(secret));
  }
  const failed = spawnSync(process.execPath, [helper, '--bad-' + marker], { env, encoding: 'utf8' });
  assert.equal(JSON.parse(failed.stdout).code, 'invalid_target');
  assert.equal(failed.stderr, '');
  assert.ok(!failed.stdout.includes(marker));
  const setup = spawnSync(process.execPath, [helper, '--configure'], { env, encoding: 'utf8', input: secret });
  assert.equal(setup.status, 1);
  assert.equal(setup.stderr, '');
  assert.ok(!setup.stdout.includes(secret));
  const installed = join(home, 'installed-skill');
  await symlink(dirname(helper), installed, process.platform === 'win32' ? 'junction' : 'dir');
  const linked = spawnSync(process.execPath, [join(installed, 'scan.mjs'), '--bad'], { env, encoding: 'utf8' });
  assert.equal(linked.status, 1);
  assert.equal(JSON.parse(linked.stdout).code, 'invalid_target');
  assert.equal(linked.stderr, '');
});
const BATCH_TARGET = 96 * 1024;

async function requestTemplate(root, key) {
  const transport = capture();
  await scan(root, key, transport.send);
  return JSON.parse(transport.requests[0].body);
}

function serialize(template, files) {
  return JSON.stringify({ ...template, state: { ...template.state, files } });
}

function assertBatchShape(result) {
  assert.deepEqual(Object.keys(result).sort(), ['batches', 'code', 'coverage_complete', 'scores', 'status']);
  result.batches.forEach((batch, i) => {
    assert.equal(batch.batch_id, i + 1);
    assert.ok(batch.file_ids.length > 0);
    assert.ok(batch.file_ids.every(id => Number.isInteger(id) && id > 0));
    const diagnostics = ['request_failed', 'authentication_failed'].includes(batch.code);
    assert.deepEqual(Object.keys(batch).sort(), ['batch_id', 'file_ids', 'status', 'code', 'scores',
      ...(diagnostics ? ['http_status', 'reason'] : [])].sort());
  });
}

test('exact full JSON boundary packs at 96 KiB and splits one byte above it', async t => {
  for (const delta of [0, 1]) {
    const { root, key } = await fixture(t);
    const template = await requestTemplate(root, key);
    const files = [{ path: 'SKILL.md', text: '' }, { path: 'a.txt', text: 'a' }];
    files[0].text = 'x'.repeat(BATCH_TARGET - Buffer.byteLength(serialize(template, files), 'utf8') + delta);
    for (const file of files) await writeFile(join(root, file.path), file.text);
    const transport = capture();
    const result = await scan(root, key, transport.send);
    assert.equal(transport.requests.length, delta ? 2 : 1);
    assert.deepEqual(transport.requests.flatMap(r => JSON.parse(r.body).state.files), files);
    assert.deepEqual(result.batches.map(b => b.file_ids), delta ? [[1], [2]] : [[1, 2]]);
    if (!delta) assert.equal(Buffer.byteLength(transport.requests[0].body, 'utf8'), BATCH_TARGET);
    assert.equal(result.code, 'complete');
    assertBatchShape(result);
  }
});

test('UTF-8 and JSON escaping count toward full request bytes', async t => {
  for (const unit of ['日', '😀', '"', '\\', '\n', '\t']) {
    const { root, key } = await fixture(t);
    const template = await requestTemplate(root, key);
    const files = [{ path: 'SKILL.md', text: '' }, { path: 'é.txt', text: 'z' }];
    const emptyBytes = Buffer.byteLength(serialize(template, files), 'utf8');
    const unitBytes = Buffer.byteLength(JSON.stringify(unit), 'utf8') - 2;
    files[0].text = unit.repeat(Math.floor((BATCH_TARGET - emptyBytes) / unitBytes) + 1);
    assert.ok(Buffer.byteLength(serialize(template, files), 'utf8') > BATCH_TARGET);
    assert.ok(files[0].text.length < BATCH_TARGET);
    for (const file of files) await writeFile(join(root, file.path), file.text);
    const transport = capture();
    const result = await scan(root, key, transport.send);
    assert.equal(transport.requests.length, 2, JSON.stringify(unit));
    assert.deepEqual(transport.requests.flatMap(r => JSON.parse(r.body).state.files), files);
    assert.deepEqual(result.batches.map(b => b.file_ids), [[1], [2]]);
  }
});

test('greedy sorted packing sends every whole file once and oversized files alone', async t => {
  const { root, key } = await fixture(t);
  const input = [
    { path: 'z.txt', text: 'last' },
    { path: 'c.txt', text: 'c'.repeat(40 * 1024) },
    { path: 'a.txt', text: 'a'.repeat(40 * 1024) },
    { path: 'b.txt', text: 'b'.repeat(300 * 1024) },
    { path: 'SKILL.md', text: 'skill' },
  ];
  for (const file of input) await writeFile(join(root, file.path), file.text);
  const transport = capture();
  const result = await scan(root, key, transport.send);
  assert.deepEqual(result.batches.map(b => b.file_ids), [[1, 2], [3], [4, 5]]);
  const files = transport.requests.flatMap(r => JSON.parse(r.body).state.files);
  assert.deepEqual(files, input.toSorted((a, b) => a.path < b.path ? -1 : 1));
  assert.equal(transport.requests.length, 3);
  transport.requests.forEach((request, i) => {
    const members = JSON.parse(request.body).state.files;
    assert.ok(members.length);
    if (i === 1) {
      assert.equal(members.length, 1);
      assert.ok(Buffer.byteLength(request.body, 'utf8') > BATCH_TARGET);
    } else assert.ok(Buffer.byteLength(request.body, 'utf8') <= BATCH_TARGET);
  });
  assert.equal(result.status, 'PASS');
  assertBatchShape(result);
});

async function singletonFixture(t, count) {
  const f = await fixture(t);
  for (let i = 0; i < count; i++) {
    await writeFile(join(f.root, i ? `${String(i).padStart(2, '0')}-${marker}.txt` : 'SKILL.md'), marker.repeat(6000));
  }
  return f;
}

function categoryAnswers(values) {
  const body = answers();
  for (const [id, value] of Object.entries(values)) body.answers[id].noul = value;
  return body;
}

test('requests are sequential and continue through findings and every failure kind', async t => {
  const outcomes = [
    () => reply(categoryAnswers({ injection: 0.95 })),
    () => new Response(JSON.stringify({ detail: { error_type: 'TokensExceeded', message: marker + secret } }), { status: 400 }),
    () => new Response(marker + secret, { status: 401 }),
    () => { throw new Error(marker + secret); },
    () => reply({ ...answers(), answers: { ...answers().answers, injection: { type: 'noul', noul: marker } } }),
    () => new Response(marker, { status: 429 }),
    () => { throw new DOMException(marker, 'TimeoutError'); },
    () => reply({ ...categoryAnswers({ exfiltration: 0.4, network: 0.19 }), batch_id: marker, file_ids: [secret], reason: marker }),
  ];
  const { root, key } = await singletonFixture(t, outcomes.length);
  const calls = [];
  let active = 0;
  const result = await scan(root, key, async (url, options) => {
    assert.equal(active, 0, 'another request started before the preceding response resolved');
    active++;
    const index = calls.length;
    calls.push(options.body);
    try {
      await new Promise(resolve => setImmediate(resolve));
      return outcomes[index]();
    } finally { active--; }
  });
  assert.equal(calls.length, outcomes.length);
  assert.equal(new Set(calls.map(body => JSON.parse(body).state.files[0].path)).size, outcomes.length);
  assert.deepEqual(result.batches.map(b => b.file_ids), outcomes.map((_, i) => [i + 1]));
  assert.deepEqual(result.batches.map(b => b.code), ['complete', 'request_failed', 'authentication_failed', 'request_failed', 'invalid_response', 'request_failed', 'request_failed', 'complete']);
  assert.deepEqual(result.batches.map(b => b.reason), [undefined, 'context_limit_exceeded', 'request_rejected', 'network_error', undefined, 'rate_limited', 'timeout', undefined]);
  assert.deepEqual(result.batches.map(b => b.http_status), [undefined, 400, 401, null, undefined, 429, null, undefined]);
  assert.equal(result.status, 'FAIL');
  assert.equal(result.code, 'partial_scan');
  assert.equal(result.coverage_complete, false);
  assert.deepEqual(result.scores, Object.fromEntries(ids.map(id => [id, ({ injection: 0.95, exfiltration: 0.4, network: 0.19 })[id] ?? 0.01])));
  for (const index of [1, 2, 3, 4, 5, 6]) assert.equal(result.batches[index].scores, null);
  assertBatchShape(result);
  const output = JSON.stringify(result);
  for (const canary of [marker, secret, root, 'SKILL.md', '.txt', 'TokensExceeded']) assert.ok(!output.includes(canary));
});

test('aggregation preserves score maxima, status precedence, and collection omissions', async t => {
  const cases = [
    { values: [0.01, 0.01], omitted: false, status: 'PASS', complete: true },
    { values: [0.2, 0.01], omitted: false, status: 'WARN', complete: true },
    { values: [0.95, 0.2], omitted: false, status: 'FAIL', complete: true },
    { values: [0.01, null], omitted: false, status: 'WARN', complete: false },
    { values: [null, null], omitted: false, status: 'WARN', complete: false },
    { values: [0.01, 0.01], omitted: true, status: 'WARN', complete: false },
    { values: [0.95, 0.01], omitted: true, status: 'FAIL', complete: false },
  ];
  for (const scenario of cases) {
    const { root, key } = await singletonFixture(t, 2);
    if (scenario.omitted) await writeFile(join(root, 'unsupported.bin'), Buffer.from([255]));
    let index = 0;
    const result = await scan(root, key, async () => {
      const value = scenario.values[index++];
      return value === null ? new Response(marker, { status: 503 }) : reply(answers(value));
    });
    assert.equal(index, 2);
    assert.equal(result.status, scenario.status);
    assert.equal(result.coverage_complete, scenario.complete);
    assert.equal(result.code, scenario.complete ? 'complete' : 'partial_scan');
    const valid = scenario.values.filter(value => value !== null);
    assert.deepEqual(result.scores, valid.length ? Object.fromEntries(ids.map(id => [id, Math.max(...valid)])) : null);
    result.batches.forEach((batch, i) => {
      if (scenario.values[i] !== null) {
        assert.equal(batch.code, 'complete');
        assert.equal(batch.status, scenario.values[i] >= 0.9 ? 'FAIL' : scenario.values[i] >= 0.2 ? 'WARN' : 'PASS');
      }
    });
    assertBatchShape(result);
  }
});
