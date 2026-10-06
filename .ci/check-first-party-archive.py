"""Run the original policy on this crate's explicit archived dependency inventory."""
from pathlib import Path
import runpy
import tomllib

policy = runpy.run_path('.github/check-first-party.py')
policy['self_test']()
# cssr has one manifest and one lock. Refuse a changed archive inventory until
# it is deliberately included; never consult an enclosing Git checkout.
paths = sorted(p for p in Path('.').rglob('Cargo.*') if p.name in {'Cargo.toml', 'Cargo.lock'})
if paths != [Path('Cargo.lock'), Path('Cargo.toml')]:
    raise SystemExit('Unexpected archived Cargo inventory')
policy['check_manifest'](tomllib.loads(Path('Cargo.toml').read_text()))
policy['check_lock'](tomllib.loads(Path('Cargo.lock').read_text())['package'])
print('Archived first-party declarations follow main; locked revisions are unique')
