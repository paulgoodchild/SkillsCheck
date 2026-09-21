import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const sha256 = data => createHash('sha256').update(data).digest('hex');

test('recorded baseline links exact versioned fixtures and prompt to live results', async () => {
  const record = JSON.parse(await readFile(new URL('../evals/results/2026-09-21-prompt-v1-suite-v1.json', import.meta.url)));
  assert.equal(record.prompt_sha256, sha256(JSON.stringify(record.prompt)));
  const cases = [];
  for (const [name, hash] of Object.entries(record.fixture_sha256)) {
    const data = await readFile(new URL(`../evals/${name}`, import.meta.url));
    assert.equal(sha256(data), hash);
    assert.ok(name.startsWith(`v${record.suite_version}/`));
    cases.push(...JSON.parse(data));
  }
  assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
  assert.deepEqual(record.results.map(r => [r.id, r.expected]).sort(), cases.map(c => [c.id, c.expected]).sort());
});

test('live runner reports mismatches and API failures truthfully without network access', async t => {
  const home = await mkdtemp(join(tmpdir(), 'skillcheck-eval-test-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const config = join(home, 'skillcheck');
  await mkdir(config);
  await writeFile(join(config, 'jev-api-key'), 'dummy-eval-key');
  const stub = join(home, 'fetch.mjs');
  for (const fails of [false, true]) {
    await writeFile(stub, `globalThis.fetch = async (url, options) => {
      if (${fails}) return new Response('UNSAFE_PROVIDER_TEXT', {status: 401});
      const questions = JSON.parse(options.body).questions;
      return new Response(JSON.stringify({answers: Object.fromEntries(Object.keys(questions).map(id => [id, {type:'noul', noul:0.01}]))}));
    };`);
    const run = spawnSync(process.execPath, ['--import', pathToFileURL(stub).href,
      fileURLToPath(new URL('../evals/run.mjs', import.meta.url))], {
      env: { ...process.env, LOCALAPPDATA: home, XDG_CONFIG_HOME: home }, encoding: 'utf8',
    });
    assert.equal(run.status, fails ? 2 : 1, run.stderr);
    assert.equal(run.stderr, '');
    const result = JSON.parse(run.stdout);
    assert.equal(result.prompt_sha256, sha256(JSON.stringify(result.prompt)));
    assert.ok(result.results.length > 0);
    for (const item of result.results) {
      const expected = fails ? 'inconclusive' : item.expected === 'unsafe' ? 'mismatched' :
        item.expected === 'context_probe' ? 'observed' : 'matched';
      assert.equal(item.outcome, expected);
    }
    assert.equal(result.summary.inconclusive, fails ? result.results.length : 0);
    assert.ok(!run.stdout.includes('dummy-eval-key'));
    assert.ok(!run.stdout.includes('UNSAFE_PROVIDER_TEXT'));
  }
});
