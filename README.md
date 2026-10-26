# rate-limit-claim-audit

Version 0.1.0 statically checks documentation about server-side request caps against Python source wiring. It never imports or executes the audited project. No runtime dependencies are needed.

Install with `python3 -m pip install .`. Run `rate-limit-claim-audit PATH` or `python3 -m rate_limit_claim_audit PATH`.

Options: `--json` emits structured results; `--verbose` lists evidence paths; repeat `--ignore GLOB` to exclude relative paths; `--fail-on HIGH` (default) or `--fail-on MEDIUM` selects the failure threshold; `--version` prints the version. Exit 0 means PASS, 2 means a finding meets the threshold, and 1 means invalid usage or an unreadable root. Medium findings remain visible with the default threshold.

The scanner reads root README.md and Markdown beneath a docs path component. Fenced blocks are excluded; inline code counts. It normalizes case, contractions, hyphens, and paragraph whitespace. Negative assertions are removed before positive assertions are checked. Each assertion family produces at most one finding.

Production evidence includes paired limiter construction and enforcement in one module or across an import edge, an explicit decorator rate, or middleware containing both a comparison and a 429 response. Source beneath tests, fixture, documentation, and example directories is excluded from production evidence. Test evidence is reported separately. Symlinks are skipped and .env files are never opened.

## Limitations

Only the scanner's exact assertion templates count. Bare nouns such as “rate limit”, “throttle”, “cap”, and “429” do not count. Client retries, backoff, and handling remote 429 responses are outside this tool's scope. Import statements, configuration, strings, comments, and counters alone do not prove enforcement. Static wiring is a heuristic, not a runtime guarantee: it does not validate reachability, configuration values, or distributed counters. Invalid source syntax is reported in warnings and supplies no evidence. No source means a positive assertion fails, while a negative assertion remains consistent.

## Development

Run `python3 -m unittest discover` and `python3 -m build`. The source distribution includes tests and fixtures. Python 3.9 or later is required.
