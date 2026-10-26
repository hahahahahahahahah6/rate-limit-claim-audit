"""Static documentation and server cap wiring checks."""
import ast
import fnmatch
import re
from pathlib import Path

POSITIVE = ('enforces rate limits', 'enforced rate limiting', 'built in rate limiting', 'requests are rate limited', 'requests are throttled', 'ip based rate limiting', 'token bucket rate limiting', 'rate limit protection', 'rate limits requests', 'throttles requests', 'request throttling', 'rate limit of', 'rate limiting', 'rate limited')
NEGATIVE = ('does not enforce rate limits', 'does not rate limit', 'does not throttle requests', 'not rate limited', 'without rate limiting', 'no rate limiting', 'no rate limits', 'unlimited requests', 'no throttling')

def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b')

def claims(text):
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append('')
        elif fence is None:
            lines.append(line)
    positive = negative = False
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        normalized = re.sub(r'\s+', ' ', paragraph.lower().replace("n't", ' not').replace('-', ' '))
        negative |= bool(pattern(NEGATIVE).search(normalized))
        positive |= bool(pattern(POSITIVE).search(pattern(NEGATIVE).sub(' ', normalized)))
    return positive, negative

def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + '.' + node.attr
    return ''

def inspect_source(path, relative):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    aliases, imports = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name
                imports.add(item.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            imports.add(module.split('.')[0])
            for item in node.names:
                aliases[item.asname or item.name] = module + '.' + item.name
                if node.level:
                    imports.add(relative.parts[0] if len(relative.parts) > 1 else item.name)
    def resolved(node):
        parts = name(node).split('.')
        return '.'.join([aliases.get(parts[0], parts[0])] + parts[1:])
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    decorators = [d for f in functions for d in f.decorator_list if isinstance(d, ast.Call)]
    lim = any(name(c.func).split('.')[-1] == 'Limiter' or resolved(c.func).split('.')[0] in {'flask_limiter', 'slowapi', 'limits'} for c in calls)
    enf = any(isinstance(d.func, ast.Attribute) and d.func.attr in {'limit', 'rate_limit'} for d in decorators)
    enf |= any(isinstance(c.func, ast.Attribute) and c.func.attr == 'init_app' for c in calls)
    middleware = [c for c in calls if name(c.func).split('.')[-1] in {'add_middleware', 'middleware'}]
    enf |= any(re.search(r'ratelimit|slowapi', name(arg), re.I) for c in middleware for arg in list(c.args) + [k.value for k in c.keywords])
    route_b = any(resolved(d.func).split('.')[-1] == 'ratelimit' and (isinstance(d.func, ast.Attribute) or resolved(d.func).split('.')[0] in {'django_ratelimit', 'ratelimit'}) and (any(k.arg == 'rate' for k in d.keywords) or any(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in d.args)) for d in decorators)
    passed = {name(a) for c in middleware if name(c.func).endswith('add_middleware') for a in list(c.args) + [k.value for k in c.keywords]}
    route_c = False
    def has429(node):
        return any(isinstance(n, ast.Constant) and type(n.value) is int and n.value == 429 for n in ast.walk(node))
    for f in functions:
        wired = f.name in passed or any(name(d.func if isinstance(d, ast.Call) else d).split('.')[-1] == 'middleware' for d in f.decorator_list)
        nodes = [n for statement in f.body for n in ast.walk(statement)]
        guard = any(isinstance(n, ast.Compare) for n in nodes)
        answer = any((isinstance(n, ast.Return) and n.value is not None and has429(n.value)) or (isinstance(n, ast.Raise) and n.exc is not None and has429(n.exc)) or (isinstance(n, ast.Call) and (name(n.func).endswith('HTTPException') and has429(n) or any(k.arg in {'status', 'status_code'} and has429(k.value) for k in n.keywords))) for n in nodes)
        route_c |= wired and guard and answer
    return {'path': relative.as_posix(), 'top': relative.parts[0][:-3] if len(relative.parts) == 1 else relative.parts[0], 'imports': imports, 'lim': lim, 'enf': enf, 'standalone': route_b or route_c}

def audit(root, ignores=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('root must be a readable directory')
    docs, prod, tests, warnings = [], [], [], []
    try:
        paths = sorted(root.rglob('*'))
        for path in paths:
            rel = path.relative_to(root)
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root) or any(fnmatch.fnmatch(rel.as_posix(), glob) for glob in ignores):
                continue
            if not path.is_file():
                continue
            if rel.as_posix() == 'README.md' or path.suffix.lower() == '.md' and 'docs' in rel.parts[:-1]:
                docs.append((rel.as_posix(), claims(path.read_text(encoding='utf-8'))))
            if path.suffix != '.py':
                continue
            if any(p in {'fixtures', 'docs', 'examples'} for p in rel.parts[:-1]):
                continue
            test = 'tests' in rel.parts[:-1] or path.name.startswith('test_') or path.name.endswith('_test.py')
            try:
                (tests if test else prod).append(inspect_source(path, rel))
            except (SyntaxError, UnicodeError) as error:
                warnings.append(str(error))
    except (OSError, UnicodeError) as error:
        raise ValueError(str(error)) from error
    def evidence(modules):
        return [m['path'] for m in modules if m['standalone'] or m['enf'] and any(l['lim'] and (l is m or l['top'] in m['imports']) for l in modules)]
    found, test_found = evidence(prod), evidence(tests)
    positive = any(c[0] for _, c in docs)
    negative = any(c[1] for _, c in docs)
    findings = []
    if positive and not found:
        findings.append({'rule': 'documented-rate-limit-claim-false', 'severity': 'MEDIUM' if test_found else 'HIGH', 'message': 'Documented server cap lacks production enforcement evidence.'})
    if negative and found:
        findings.append({'rule': 'documented-no-rate-limit-claim-false', 'severity': 'HIGH', 'message': 'Documentation denies server caps but production enforcement exists.'})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'verdict': 'FAIL' if failed else 'PASS', 'findings': findings, 'claims': {'positive': positive, 'negative': negative}, 'evidence': found, 'test_evidence': test_found, 'warnings': warnings}
