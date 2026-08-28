#!/usr/bin/env bash
set -euo pipefail

python - <<'PY'
import json
from pathlib import Path

path = Path('.amo')
data = json.loads(path.read_text(encoding='utf-8'))
assert data.get('schema') == 'desarrollamo.amo.v1'
assert data.get('id') == 'storeamo-verify'
checks = data.get('health', {}).get('checks', [])
assert isinstance(checks, list) and checks
assert any(c.get('command') == 'bash scripts/autocheck.sh' for c in checks if isinstance(c, dict))
assert data.get('policy', {}).get('self_declared_pass_allowed') is False
PY

python -m py_compile verify_catalog.py
python verify_catalog.py tests/fixture-catalog.json
