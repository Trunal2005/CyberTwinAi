"""Read-only local-server smoke test; creates/revokes its own login session and audits exports."""
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()
root = Path(__file__).resolve().parents[1]
output = root / 'data' / 'smoke'
output.mkdir(parents=True, exist_ok=True)
with httpx.Client(base_url='http://127.0.0.1:8000', timeout=60) as client:
    response = client.post('/api/auth/login', json={
        'username': os.environ['ADMIN_USERNAME'], 'password': os.environ['ADMIN_PASSWORD'],
    })
    response.raise_for_status()
    try:
        for path in ['/api/health', '/api/status', '/api/overview', '/api/events',
                     '/api/network', '/api/twin/scenarios', '/api/ml/metrics', '/api/reports']:
            response = client.get(path)
            response.raise_for_status()
            print(f'PASS {path}')
        for format in ['json', 'csv', 'pdf']:
            response = client.get('/api/reports/export', params={'format': format})
            response.raise_for_status()
            (output / f'report.{format}').write_bytes(response.content)
            print(f'PASS {format.upper()} export ({len(response.content)} bytes)')
        schema = client.get('/openapi.json')
        schema.raise_for_status()
        (root / 'docs' / 'openapi.json').write_text(json.dumps(schema.json(), indent=2), encoding='utf-8')
        print('PASS OpenAPI snapshot')
    finally:
        client.post('/api/auth/logout').raise_for_status()
