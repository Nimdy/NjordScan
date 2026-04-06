# Architecture Overview

NjordScan's architecture, components, and how they fit together.

---

## Design Principles

- **Modularity** — each security concern is a separate scan module
- **Graceful degradation** — missing dependencies don't crash the scanner
- **Extensibility** — custom patterns and plugins without modifying core code
- **Reliability** — circuit breakers, rate limiting, and retry logic protect against failures

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│                   CLI Interface                         │
│  cli.py — Click commands, Rich terminal output          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                 Scan Orchestrator                        │
│  scanner.py — coordinates modules, caching, reporting   │
└──┬──────────┬──────────┬──────────┬─────────────────────┘
   │          │          │          │
┌──▼──┐  ┌───▼──┐  ┌───▼───┐  ┌──▼──────────┐
│Stat.│  │Deps  │  │Supply │  │Headers/     │
│Anal.│  │Module│  │Chain  │  │Runtime/AI   │
│     │  │      │  │Module │  │Endpoints    │
└─────┘  └──────┘  └───────┘  └─────────────┘
   Static modules              Dynamic modules

┌─────────────────────────────────────────────────────────┐
│               Core Infrastructure                       │
│  Circuit Breaker │ Rate Limiter │ Cache Manager          │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   Reporting                             │
│  Terminal │ JSON │ HTML │ SARIF │ Markdown │ SBOM       │
└─────────────────────────────────────────────────────────┘
```

---

## Core Components

### Scan Orchestrator
**Location**: `njordscan/scanner.py`

The central coordinator. On `scan()`:
1. Detects framework (Next.js/React/Vite)
2. Loads modules based on scan mode
3. Runs modules concurrently
4. Optionally enhances results with heuristic analysis
5. Calculates NjordScore
6. Formats and outputs report

```python
class ScanOrchestrator:
    def __init__(self, config: Config):
        self.modules: Dict[str, BaseModule] = {}
        self.cache_manager = CacheManager()
        self.report_formatter = ReportFormatter()
```

### Configuration
**Location**: `njordscan/config.py`

Dataclass with 60+ options. Loaded from:
1. CLI arguments (highest priority)
2. `.njordscan.json` config file
3. Environment variables
4. Defaults

---

## Scanning Modules

All modules inherit from `BaseModule` (`njordscan/modules/base.py`):

```python
class BaseModule(ABC):
    @abstractmethod
    async def scan(self, target: str) -> List[Vulnerability]:
        pass

    def should_run(self, mode: str) -> bool:
        # Controls which modes this module runs in
```

### Module Registry

Modules register in `njordscan/modules/__init__.py` via `MODULE_REGISTRY`:

| Module | File | Runs In | What It Does |
|--------|------|---------|-------------|
| `configs` | `configs.py` | static, full | Scans config files for secrets, insecure settings |
| `static` | `code_static.py` | static, full | Regex-based XSS, injection, eval, secrets detection |
| `static_enhanced` | `code_static_enhanced.py` | static, full | Pattern engine integration for deeper analysis |
| `dependencies` | `dependencies.py` | static, full | npm audit, typosquatting, outdated packages |
| `supply_chain` | `supply_chain.py` | static, full | Install script analysis, lockfile integrity |
| `headers` | `headers.py` | dynamic, full | HTTP security headers (CSP, HSTS, etc.) |
| `runtime` | `runtime.py` | dynamic, full | DAST with test payloads against live apps |
| `ai_endpoints` | `ai_endpoints.py` | dynamic, full | Probes for exposed AI/LLM endpoints |

### Mode Mapping

CLI modes map to module modes:
- `quick` / `standard` -> `static` (configs, static, dependencies, supply_chain)
- `deep` / `enterprise` -> `full` (all modules)

---

## Heuristic Analysis (`njordscan/ai/`)

Despite the package name, this layer uses **regex matching, string similarity, and statistical scoring** — not ML or LLMs.

| Component | File | What It Actually Does |
|-----------|------|----------------------|
| Package Analyzer | `ai_package_analyzer.py` | Regex + SequenceMatcher for typosquatting, obfuscation scoring |
| Code Fingerprinting | `ai_code_fingerprinting.py` | Regex patterns for obfuscated/minified code detection |
| Code Understanding | `code_understanding.py` | Lexical features: LOC, comment ratio, entropy |
| Similarity Analyzer | `package_similarity_analyzer.py` | Levenshtein-like distance for package name comparison |
| Maintainer Profiler | `maintainer_profile_analyzer.py` | Heuristic checks on maintainer metadata |
| Security Advisor | `security_advisor.py` | Lookup-table recommendations by vuln type |
| Orchestrator | `ai_orchestrator.py` | Coordinates all the above |

---

## Pattern Engine
**Location**: `njordscan/analysis/pattern_engine.py`

The pattern engine provides structured security detection with:
- 11+ built-in patterns (XSS, SQLi, command injection, secrets, SSRF)
- Context-aware matching (framework detection, user input sources)
- Exclusion patterns to reduce false positives
- CWE and OWASP category mapping per pattern
- Custom pattern registration via `engine.add_pattern()`

```python
engine = PatternEngine()  # Loads built-in patterns
matches = engine.analyze_file(Path("app.js"), code_content)
# Returns List[PatternMatch] with line numbers, severity, CWE IDs
```

---

## Core Infrastructure

### Circuit Breaker (`njordscan/core/circuit_breaker.py`)
Prevents cascading failures. State machine: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.
Configurable failure threshold, recovery timeout, and success threshold.

### Rate Limiter (`njordscan/core/rate_limiter.py`)
Three algorithms: token bucket, sliding window, and adaptive (auto-adjusts based on error rate and response times). Per-endpoint rate limiting via `GlobalRateLimiter`.

### Cache Manager (`njordscan/cache.py`)
File-based caching with strategies: off, basic, intelligent, aggressive. Caches scan results keyed by target + config hash.

### Retry Handler (`njordscan/core/retry_handler.py`)
Exponential backoff with configurable max retries for transient failures.

---

## Framework Detection
**Location**: `njordscan/frameworks/framework_detector.py`

Auto-detects project framework by scanning for:
- Next.js: `next.config.js`, `pages/`, `app/`, Next.js imports
- React: `react` in dependencies, JSX files
- Vite: `vite.config.*`, Vite imports

Framework-specific analyzers (`nextjs_analyzer.py`, `react_analyzer.py`, `vite_analyzer.py`) add targeted patterns.

---

## Plugin System
**Location**: `njordscan/plugins.py`

Plugins are loaded from `plugins/` directories. A plugin is any Python module with a `scan()` method:

```python
class MyPlugin:
    async def scan(self, target: str) -> List[dict]:
        # Return list of vulnerability dicts
```

Plugins are enabled via config and validated for framework compatibility before execution.

---

## Reporting

### Report Formatter (`njordscan/report/formatter.py`)
Formats scan results into: Terminal (Rich), JSON, HTML, SARIF, Markdown, Text.

### SBOM Generation (`njordscan/dependencies/sbom_generator.py`)
Generates Software Bill of Materials in CycloneDX and SPDX formats. Wired into CLI via `--sbom` and `--sbom-format`.

### CI/CD Integration
The `--ci` flag enables non-interactive mode. Combined with `--fail-on <severity>`, it returns non-zero exit codes when findings exceed the threshold — suitable for GitHub Actions, GitLab CI, Jenkins, etc.

---

## Data Flow

```
CLI (cli.py)
  -> Config (config.py)
  -> ScanOrchestrator (scanner.py)
    -> Framework detection
    -> Load modules based on mode
    -> Run modules concurrently
    -> Collect List[Vulnerability]
    -> Optional: heuristic enhancement
    -> Calculate NjordScore
    -> Format report
    -> Cache results
  -> Output (terminal / file / CI exit code)
```

---

## Vulnerability Model

Every finding is a `Vulnerability` object (`njordscan/vulnerability.py`) with:
- `id`, `title`, `severity`, `confidence`
- `vuln_type` — maps to `VulnerabilityType` enum with CWE/OWASP metadata
- `file_path`, `line_number`, `code_snippet`
- `fix` — remediation guidance
- `metadata` — module-specific details

35+ standardized vulnerability types in `njordscan/vulnerability_types.py`, each mapped to CWE codes and OWASP Top 10 2021 categories.
