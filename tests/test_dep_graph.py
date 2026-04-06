#!/usr/bin/env python3
"""
Tests for dependency graph analysis.
"""

import pytest
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.analysis.dep_graph import DepGraphAnalyzer, KNOWN_MALICIOUS


@pytest.fixture
def analyzer():
    return DepGraphAnalyzer()


def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f)


# --------------------------------------------------------------------- #
#  Graph parsing
# --------------------------------------------------------------------- #

class TestGraphParsing:

    def test_parse_v2_lockfile(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"lodash": "^4.17.21"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        assert result is not None
        assert result.total_packages == 1
        assert 'lodash' in result.graph

    def test_parse_v1_lockfile(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"express": "^4.18.0"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        assert result is not None
        assert 'express' in result.graph

    def test_no_lockfile_returns_none(self, analyzer, tmp_path):
        result = analyzer.analyze(tmp_path)
        assert result is None

    def test_direct_vs_transitive_depth(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"express": "^4.18.0"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-x==",
                    "dependencies": {"body-parser": "1.20.0"}
                },
                "node_modules/body-parser": {
                    "version": "1.20.0",
                    "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.0.tgz",
                    "integrity": "sha512-y=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        assert result.direct_count >= 1
        assert result.total_packages == 2


# --------------------------------------------------------------------- #
#  Risk scoring
# --------------------------------------------------------------------- #

class TestRiskScoring:

    def test_known_malicious_high_score(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"event-stream": "3.3.6"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/event-stream": {
                    "version": "3.3.6",
                    "resolved": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        malicious = [r for r in result.risks if r.name == 'event-stream']
        assert len(malicious) == 1
        assert malicious[0].risk_score >= 0.7
        assert malicious[0].severity in ('critical', 'high')

    def test_missing_integrity_flagged(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"foo": "1.0.0"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/foo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        risks = [r for r in result.risks if r.name == 'foo']
        assert len(risks) == 1
        assert any('integrity' in f.lower() for f in risks[0].risk_factors)

    def test_non_standard_registry_flagged(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"evil": "1.0.0"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/evil": {
                    "version": "1.0.0",
                    "resolved": "https://evil-registry.com/evil-1.0.0.tgz",
                    "integrity": "sha512-x=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        risks = [r for r in result.risks if r.name == 'evil']
        assert len(risks) == 1
        assert any('registry' in f.lower() for f in risks[0].risk_factors)

    def test_safe_package_no_risk(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"lodash": "^4.17.21"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        lodash_risks = [r for r in result.risks if r.name == 'lodash']
        assert len(lodash_risks) == 0  # Safe, no risk factors

    def test_git_dependency_flagged(self, analyzer, tmp_path):
        write_json(tmp_path / 'package.json', {
            "name": "test", "dependencies": {"priv": "1.0.0"}
        })
        write_json(tmp_path / 'package-lock.json', {
            "name": "test", "lockfileVersion": 2,
            "packages": {
                "": {"name": "test"},
                "node_modules/priv": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/priv.git#abc123"
                }
            }
        })
        result = analyzer.analyze(tmp_path)
        risks = [r for r in result.risks if r.name == 'priv']
        assert len(risks) >= 1
        assert any('git' in f.lower() for f in risks[0].risk_factors)
