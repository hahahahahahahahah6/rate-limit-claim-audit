import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from rate_limit_claim_audit import audit
from rate_limit_claim_audit.core import claims, POSITIVE, NEGATIVE

ROOT = Path(__file__).resolve().parents[1]
A = 'limiter = Limiter()\n@limiter.limit("100/minute")\ndef route(): pass\n'
C = 'def guard(request):\n    if count > cap:\n        return Response(status_code=429)\napp.add_middleware(guard)\n'

class AuditTests(unittest.TestCase):
    def project(self, doc='rate limiting', files=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'README.md').write_text(doc)
        for name, content in (files or {}).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def check(self, doc='rate limiting', files=None, severity=None):
        result = audit(self.project(doc, files))
        self.assertEqual(len(result['findings']), int(severity is not None))
        if severity:
            self.assertEqual(result['findings'][0]['severity'], severity)
        else:
            self.assertEqual(result['verdict'], 'PASS')
        return result

    def cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'rate_limit_claim_audit', *map(str, args)], capture_output=True, text=True)

    def test_01_one_module(self):
        root = ROOT / 'tests/fixtures/good'
        self.assertEqual(self.cli(root).returncode, 0)
        self.check('enforces rate limits', {'app.py': A})

    def test_02_split(self):
        self.check(files={'limiter.py': 'lim = Limiter()', 'app.py': 'import limiter\n@limiter.limit("1/m")\ndef f(): pass'})

    def test_03_init(self):
        self.check('built-in rate limiting', {'app.py': 'lim = Limiter()\nlim.init_app(app)'})

    def test_04_decorator(self):
        self.check('requests are rate limited', {'app.py': 'from django_ratelimit.decorators import ratelimit\n@ratelimit(rate="10/m")\ndef f(): pass'})

    def test_05_guard(self):
        self.check('rate limits requests', {'app.py': C})

    def test_06_limiter_only(self):
        result = self.cli(ROOT / 'tests/fixtures/bad', '--json')
        self.assertEqual(result.returncode, 2)
        finding = json.loads(result.stdout)['findings']
        self.assertEqual([(f['rule'], f['severity']) for f in finding], [('documented-rate-limit-claim-false', 'HIGH')])

    def test_07_orphan(self):
        self.check(files={'app.py': '@limiter.limit("1/m")\ndef f(): pass'}, severity='HIGH')

    def test_08_import(self):
        self.check(files={'app.py': 'import flask_limiter'}, severity='HIGH')

    def test_09_client_retry(self):
        self.check(files={'app.py': 'from tenacity import retry\nimport backoff\n@retry()\n@backoff.on_exception(backoff.expo, Exception)\ndef f():\n    if response.status_code == 429:\n        return requests.get(url)'}, severity='HIGH')

    def test_10_redis(self):
        self.check(files={'app.py': 'redis.incr(key)'}, severity='HIGH')

    def test_11_negative(self):
        result = self.check('no rate limiting', {'app.py': A}, 'HIGH')
        self.assertEqual(result['findings'][0]['rule'], 'documented-no-rate-limit-claim-false')
        self.assertEqual(result['verdict'], 'FAIL')

    def test_12_no_claim(self):
        self.check('A server.', {'app.py': A})

    def test_13_client_claim(self):
        self.check('retries with backoff on 429', {'app.py': 'requests.get(url)'})

    def test_14_no_source(self):
        self.check('enforces rate limits', severity='HIGH')
        self.check('no rate limiting')

    def test_15_non_evidence(self):
        cases = ['while True:\n    time.sleep(1)\n    requests.get(url)', '"429"', 'class RateLimiter: pass', 'config = {"RATE_LIMIT": 100}', 'from ratelimit import ratelimit\n@ratelimit\ndef f(): pass', 'def f():\n    if x > 1: return 200\napp.add_middleware(f)', 'def f(): return 429\napp.add_middleware(f)', 'headers = {"Retry-After": "10"}', 'asyncio.sleep(1)']
        for source in cases:
            with self.subTest(source=source):
                self.check(files={'app.py': source}, severity='HIGH')

    def test_16_unpaired(self):
        self.check(files={'a.py': 'lim = Limiter()', 'b.py': '@lim.limit("1/m")\ndef f(): pass'}, severity='HIGH')

    def test_17_tests_only(self):
        root = self.project(files={'tests/app.py': A})
        self.assertEqual(audit(root)['findings'][0]['severity'], 'MEDIUM')
        self.assertEqual(self.cli(root).returncode, 0)
        self.assertEqual(self.cli(root, '--fail-on', 'MEDIUM').returncode, 2)

    def test_18_fences(self):
        self.check('```text\nrate limiting\n```')
        self.check('~~~\nrate limiting\n~~~')
        self.check('`rate limiting`', severity='HIGH')

    def test_19_negation(self):
        self.assertEqual(claims('does not rate limit'), (False, True))
        self.assertEqual(claims("doesn't enforce rate limits"), (False, True))

    def test_20_bare(self):
        self.check('rate limit / throttle / 429')

    def test_21_cli(self):
        root = self.project('A server.', {'app.py': A, 'docs/claim.md': 'rate limiting'})
        self.assertEqual(self.cli('--version').stdout.strip(), '0.1.0')
        self.assertEqual(json.loads(self.cli(root, '--json').stdout)['verdict'], 'PASS')
        self.assertIn('app.py', self.cli(root, '--verbose').stdout)
        self.assertEqual(self.cli(root, '--ignore', 'docs/*').returncode, 0)
        self.assertEqual(self.cli(root / 'missing').returncode, 1)
        self.assertEqual(self.cli('--invalid').returncode, 1)
        bad = self.project('A server.', {'docs/claim.md': 'rate limiting'})
        self.assertEqual(self.cli(bad).returncode, 2)
        self.assertEqual(self.cli(bad, '--ignore', 'docs/*').returncode, 0)

    def test_22_self(self):
        result = audit(ROOT)
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['claims'], {'positive': False, 'negative': False})
        self.assertEqual(self.cli(ROOT).returncode, 0)

    def test_23_env(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.assertEqual(audit(ROOT)['verdict'], 'PASS')

    def test_24_packaging(self):
        for path in list(ROOT.rglob('*.py')) + [ROOT / 'README.md']:
            if any(p in {'build', 'dist', '.venv'} or p.endswith('.egg-info') for p in path.parts):
                continue
            self.assertIsNone(re.search(r'\b' + 'py' + r'thon\b', path.read_text()), str(path))
        self.assertIn('setuptools>=77', (ROOT / 'pyproject.toml').read_text())
        self.assertIn('license = "MIT"', (ROOT / 'pyproject.toml').read_text())
        self.assertIn('recursive-include tests', (ROOT / 'MANIFEST.in').read_text())

    def test_25_aliases(self):
        self.check(files={'app.py': 'from slowapi import Limiter as Cap\nl = Cap()\nl.init_app(app)'})
        self.check(files={'app.py': 'import slowapi as s\nl = s.Limiter()\napp.add_middleware(SlowAPIMiddleware)'})

    def test_26_guard_variants(self):
        self.check(files={'app.py': '@app.middleware("http")\nasync def guard(req):\n    if count > 10:\n        raise HTTPException(429)'})
        self.check(files={'app.py': 'from ratelimit import ratelimit as cap\n@cap("10/m")\ndef f(): pass'})

    def test_27_exclusions(self):
        for name in ['examples/app.py', 'docs/app.py', 'fixtures/app.py']:
            self.check(files={name: A}, severity='HIGH')
        root = self.project(files={'test_app.py': A})
        self.assertEqual(audit(root)['findings'][0]['severity'], 'MEDIUM')
        outside = self.project(files={'app.py': A})
        root = self.project()
        (root / 'linked.py').symlink_to(outside / 'app.py')
        self.assertEqual(audit(root)['findings'][0]['severity'], 'HIGH')

    def test_28_all_templates(self):
        for phrase in POSITIVE:
            self.assertEqual(claims(phrase), (True, False))
        for phrase in NEGATIVE:
            self.assertEqual(claims(phrase), (False, True))
        self.assertEqual(claims('ENFORCES rate-\nlimits'), (True, False))
        self.assertEqual(claims('rate\n\nlimiting'), (False, False))
        self.assertEqual(claims('prerate limitingextra'), (False, False))

    def test_29_both_families(self):
        result = self.check('rate limiting. no throttling.', severity='HIGH')
        self.assertEqual(result['claims'], {'positive': True, 'negative': True})

    def test_30_docs_negative(self):
        self.check('A server.', {'app.py': A, 'tests/docs/note.md': 'no throttling'}, 'HIGH')
