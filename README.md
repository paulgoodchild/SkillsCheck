# SkillCheck

Check AI agent skills on disk before installation, or audit installed skills, for malicious instructions and unsafe code using [TypeSafe Jev](https://docs.typesafe.ai/api).

The helper sends skill text to Jev without loading it into the agent's context or executing it. Results contain only verdicts, scores, coverage, numeric batch/file IDs and fixed error reasons. **Submitted text is not redacted for secrets.**

## Install

Requires an agent that supports skills and local command execution, a [Jev API key](https://console.typesafe.ai), and internet access. Uses Node.js with no additional npm dependencies.

```bash
npx skills@latest add paulgoodchild/SkillsCheck -g
```

## Use

Ask your agent:

```text
Use skillcheck to inspect /absolute/path/to/skill
```

Supply a skill directory or its SKILL.md path.

On first use, the agent provides the helper's path. Run this in **your own terminal**, replacing the placeholder:

```text
node "<absolute-path-to-SkillCheck>/scan.mjs" --configure
```

Input is hidden; the key is saved locally and reused. Never paste it into chat. Ask the agent to rerun the scan after setup. Use the same command to replace a rejected key.

## Results

- **PASS:** All category scores below 20%, with complete coverage.
- **WARN:** No FAIL signal, but a score of 20%–<90%, incomplete coverage, or a failed request.
- **FAIL:** At least one category scored 90% or higher, even if coverage is incomplete.

The agent shows all eight risk categories in a probability table, followed by flagged batches and failures. Scores are Jev's estimates, not severity or proof of wrongdoing. Overall scores are the highest per category across assessed batches; they are not whole-skill probabilities. A batch result does not identify an offending file within it.

Request failures include a fixed reason and the HTTP status when available. Reasons distinguish context/size rejection, rate limiting, billing, service errors, timeouts, and connection failures. Raw API errors are never displayed.

PASS does not guarantee safety. Thresholds are provisional; classifier accuracy has not been calibrated.

The scanner skips VCS internals and media files identified as binary. Skipped dependencies, nested links, unreadable files, and unsupported material prevent PASS. Text disguised as media is still checked.

Whole files are packed toward a **96 KiB serialized-request target** and sent sequentially. Larger files go alone; files are never split. Failed batches do not stop later requests, and successful assessments remain available. No automatic retries.

The size target is not a token estimate or rejection limit. Jev may reject an oversized file; relationships across batches may be missed. A 256-entry traversal guard stops collection before requests. There is no aggregate text-byte cap.

## Tests

```bash
node --test tests/*.test.mjs
```

Tests use dummy credentials and simulated API responses.

For malicious and benign samples, versioned live results, and an optional Jev runner, see [evals](evals/README.md).
