import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan, PROMPT_VERSION } from '../skillcheck/scan.mjs';

const suiteVersion = 1;
const sha256 = data => createHash('sha256').update(data).digest('hex');
const startedAt = new Date().toISOString();
const fixtureHashes = {};
const cases = [];
for (const group of ['benign', 'malicious', 'context']) {
  const name = `v${suiteVersion}/${group}/examples.json`;
  const data = await readFile(new URL(name, import.meta.url));
  fixtureHashes[name] = sha256(data);
  cases.push(...JSON.parse(data));
}

const home = await mkdtemp(join(tmpdir(), 'skillcheck-evals-'));
const results = [];
let promptHash = null;
let prompt = null;
try {
  for (const item of cases) {
    // Fixtures are data, never executable modules or installable skills.
    if (!/^[a-z0-9_]+$/.test(item.id) || !['benign', 'unsafe', 'context_probe'].includes(item.expected)) throw new Error('invalid_fixture');
    const root = join(home, item.id);
    await mkdir(root);
    for (const [name, content] of Object.entries(item.files)) {
      if (!/^[a-zA-Z0-9_.-]+$/.test(name) || name === '.' || name === '..' || typeof content !== 'string') throw new Error('invalid_fixture');
      await writeFile(join(root, name), content);
    }
    const result = await scan(root, undefined, async (url, options) => {
      const request = JSON.parse(options.body);
      prompt = request.questions;
      promptHash = sha256(JSON.stringify(request.questions));
      return fetch(url, options);
    });
    const assessed = result.coverage_complete && result.scores !== null;
    const outcome = !assessed ? 'inconclusive' : item.expected === 'context_probe' ? 'observed' :
      (item.expected === 'benign' ? result.status === 'PASS' : result.status !== 'PASS') ? 'matched' : 'mismatched';
    results.push({ id: item.id, expected: item.expected, outcome, ...result });
  }
  const summary = Object.fromEntries(['matched', 'mismatched', 'inconclusive', 'observed'].map(outcome =>
    [outcome, results.filter(result => result.outcome === outcome).length]));
  const report = {
    started_at: startedAt, finished_at: new Date().toISOString(),
    suite_version: suiteVersion, prompt_version: PROMPT_VERSION,
    model_alias: 'jev-latest', resolved_model_version: null,
    helper_sha256: sha256(await readFile(new URL('../skillcheck/scan.mjs', import.meta.url))),
    prompt_sha256: promptHash, prompt, fixture_sha256: fixtureHashes, summary, results,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = summary.inconclusive ? 2 : summary.mismatched ? 1 : 0;
} finally {
  await rm(home, { recursive: true, force: true });
}
