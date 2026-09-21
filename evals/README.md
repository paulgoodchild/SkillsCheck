# Live Jev evaluations

Small synthetic cases for checking prompt changes. Samples are **data**, including malicious instructions; the runner submits their text through SkillCheck and never executes it. Live runs use your Jev account and may incur charges.

This directory is repository-only. The skills installer discovers `skillcheck/SKILL.md` and packages its sibling `scan.mjs`; evals, recorded results and tests are outside that skill directory. Keep examples as JSON, not installable `SKILL.md` files.

## Run

From the repository root, configure a key once in your own terminal:

```sh
node skillcheck/scan.mjs --configure
node evals/run.mjs > evals/results/local.json
```

The second command runs all 19 cases sequentially with the repository's current scanner. `local.json` is ignored by Git and overwritten on each run; rename it before rerunning to retain evidence. Offline tests remain `node --test tests/*.test.mjs`.

- `v1/malicious/`: seven unsafe examples; a valid WARN or FAIL counts as detected.
- `v1/benign/`: eleven ordinary operations; expected PASS.
- `v1/context/`: one missing-context probe; observe its scores without a pass/fail expectation.
- `results/`: recorded live results, including every category score and request failure.

For completed reports, exit codes are **0** expectations matched, **1** mismatches with no incomplete assessments, and **2** at least one incomplete assessment. A runner crash may exit without a report. API errors never count as successful attack detection. Review individual WARN/FAIL verdicts; detection alone does not mean high confidence.

## Versions

Results record the suite version, `PROMPT_VERSION` from the helper, the exact questions, fixture/question hashes, and the helper hash. They name the requested `jev-latest` alias; the helper does not expose the resolved provider model version, so that field is null. Results may vary as the model changes.

- Keep published suites unchanged. Copy the complete suite into the next version directory (for example, `v2/`), edit there, and update `suiteVersion` in `evals/run.mjs`.
- When Jev question wording, shared instructions or criteria change, increment `PROMPT_VERSION` in `skillcheck/scan.mjs` and record what changed and why in [PROMPT_CHANGELOG.md](PROMPT_CHANGELOG.md). Report formatting alone does not change the Jev prompt version.
- Retain results as new files; do not overwrite earlier evidence. Hashes distinguish content even if someone forgets to bump a version. Embedded questions and versioned fixtures keep comparisons self-contained.

The [baseline](results/2026-09-21-prompt-v1-suite-v1.json) is an imported actual live run: 11 benign PASS; seven unsafe detections (six FAIL, one WARN); one context WARN. Version metadata, the unchanged questions and fixture hashes were attached when publishing these recorded results. Its helper hash fingerprints that run's scanner.

A [fresh run of this runner](results/2026-09-21-reproduction-prompt-v1-suite-v1.json) reproduced those verdicts: 18 expectations matched, no mismatches or incomplete assessments, and one context observation.

These examples are not a representative benchmark. Several informed prompt development; later examples broadened the checks. Results do not establish production accuracy or calibrated risk probabilities.
