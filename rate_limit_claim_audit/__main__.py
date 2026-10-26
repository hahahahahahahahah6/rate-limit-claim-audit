import argparse
import json
import sys
from . import __version__, audit

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, '{}: error: {}\n'.format(self.prog, message))

def main(argv=None):
    parser = Parser(description='Audit documented server-side request caps.')
    parser.add_argument('root')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='HIGH')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore, args.fail_on)
    except ValueError as error:
        parser.exit(1, 'error: {}\n'.format(error))
    if args.json:
        print(json.dumps(result))
    else:
        print(result['verdict'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        if args.verbose:
            print('Evidence: ' + ', '.join(result['evidence']))
            print('Test evidence: ' + ', '.join(result['test_evidence']))
            for warning in result['warnings']:
                print('Warning: ' + warning)
    return 2 if result['verdict'] == 'FAIL' else 0

if __name__ == '__main__':
    sys.exit(main())
