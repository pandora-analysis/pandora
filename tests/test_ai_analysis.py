from __future__ import annotations

import tempfile
import unittest

import importlib.util
import sys
import types

from enum import IntEnum, auto
from pathlib import Path


class _Status(IntEnum):
    ERROR = auto()
    CLEAN = auto()
    WARN = auto()
    ALERT = auto()


def _load_analyze():
    root = Path(__file__).resolve().parents[1]
    module_path = root / 'pandora' / 'workers' / 'ai_analysis' / 'ai_analysis.py'

    pandora_module = types.ModuleType('pandora')
    pandora_module.__path__ = [str(root / 'pandora')]
    workers_module = types.ModuleType('pandora.workers')
    workers_module.__path__ = [str(root / 'pandora' / 'workers')]
    helpers_module = types.ModuleType('pandora.helpers')
    helpers_module.Status = _Status
    report_module = types.ModuleType('pandora.report')
    report_module.Report = object
    task_module = types.ModuleType('pandora.task')
    task_module.Task = object
    base_module = types.ModuleType('pandora.workers.base')
    base_module.BaseWorker = object

    sys.modules.update({
        'pandora': pandora_module,
        'pandora.workers': workers_module,
        'pandora.helpers': helpers_module,
        'pandora.report': report_module,
        'pandora.task': task_module,
        'pandora.workers.base': base_module,
    })

    spec = importlib.util.spec_from_file_location('pandora.workers.ai_analysis.ai_analysis', module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.analyze


analyze = _load_analyze()


class AIAnalysisTests(unittest.TestCase):

    def _write_sample(self, content: str | bytes) -> Path:
        sample = Path(self.tmpdir.name) / 'sample.txt'
        if isinstance(content, bytes):
            sample.write_bytes(content)
        else:
            sample.write_text(content, encoding='utf-8')
        return sample

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_clean_file_returns_zero_score(self) -> None:
        result = analyze(self._write_sample('hello = "world"\n'))

        self.assertEqual(result['score'], 0.0)
        self.assertEqual(result['risk'], 'none')
        self.assertEqual(result['issues'], [])
        self.assertIn('No obvious', result['summary'])

    def test_missing_file_returns_safe_error_dict(self) -> None:
        result = analyze(Path(self.tmpdir.name) / 'missing.txt')

        self.assertEqual(result['score'], 0.0)
        self.assertIn('error', result)
        self.assertIn('Unable to read file', result['summary'])

    def test_invalid_utf8_is_scanned_safely(self) -> None:
        result = analyze(self._write_sample(b'\xff\xfe password="supersecret"\n'))

        self.assertGreater(result['score'], 0.0)
        self.assertEqual(result['risk'], 'high')
        self.assertEqual(result['issues'][0]['id'], 'hardcoded_password')

    def test_critical_secret_is_masked(self) -> None:
        result = analyze(self._write_sample('OPENAI_API_KEY=sk-proj-abcdefghijklmnop\n'))

        self.assertEqual(result['risk'], 'high')
        matches = [issue['match'] for issue in result['issues']]
        self.assertTrue(any('****' in match for match in matches))
        self.assertFalse(any('abcdefghijklmnop' in match for match in matches))

    def test_line_numbers_are_reported(self) -> None:
        result = analyze(self._write_sample('first line\nsecond line\npassword="supersecret"\n'))

        password_issue = next(issue for issue in result['issues'] if issue['id'] == 'hardcoded_password')
        self.assertEqual(password_issue['line'], 3)

    def test_score_is_capped_at_one(self) -> None:
        content = '\n'.join([
            'password="supersecret"',
            'api_key="abcdefghijklmnop"',
            'AWS_SECRET_ACCESS_KEY="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"',
            'jwt_secret="abcdefghijk"',
        ])
        result = analyze(self._write_sample(content))

        self.assertEqual(result['score'], 1.0)
        self.assertEqual(result['risk'], 'high')
        self.assertGreaterEqual(len(result['issues']), 4)

    def test_medium_risk_without_high_or_critical(self) -> None:
        result = analyze(self._write_sample('debug=true\n'))

        self.assertEqual(result['risk'], 'medium')
        self.assertGreater(result['score'], 0.0)


if __name__ == '__main__':
    unittest.main()
