"""Import weight and packaging promises."""

import subprocess
import sys
from pathlib import Path

import panoptes

ROOT = Path(panoptes.__file__).parent


def run(code):
    return subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True,
        cwd=str(ROOT.parent),
    )


def test_importing_the_store_loads_neither_yaml_nor_an_http_client():
    result = run(
        "import sys\n"
        "import panoptes\n"
        "from panoptes import AuditDB, validate_event, SCHEMA_VERSION\n"
        "from panoptes.hooks import ProxyHooks, Reject, Upstream\n"
        "bad = [m for m in ('yaml', 'httpx', 'panoptes.proxy') if m in sys.modules]\n"
        "print(bad)\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_the_policy_engine_and_its_names_are_gone():
    result = run(
        "import importlib.util, panoptes\n"
        "assert importlib.util.find_spec('panoptes.policy') is None\n"
        "assert not hasattr(panoptes, 'PolicyEngine')\n"
        "try:\n    panoptes.Nope\nexcept AttributeError:\n    print('ok')\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_the_package_needs_no_third_party_dependency():
    pyproject = (ROOT.parent / "pyproject.toml").read_text()
    assert "dependencies = []" in pyproject
    assert "yaml" not in pyproject.lower()
    assert not (ROOT / "default_policies").exists()


def test_the_ingest_server_does_not_need_the_proxy_module():
    result = run(
        "import sys\nfrom panoptes._server import BoundedThreadingHTTPServer\n"
        "print('panoptes.proxy' in sys.modules, 'httpx' in sys.modules)\n"
    )
    assert result.stdout.strip() == "False False"


def test_the_package_is_marked_typed():
    assert (ROOT / "py.typed").is_file()
    pyproject = (ROOT.parent / "pyproject.toml").read_text()
    assert "py.typed" in pyproject


def test_the_proxy_extra_carries_httpx():
    pyproject = (ROOT.parent / "pyproject.toml").read_text()
    assert "[project.optional-dependencies]\nproxy = [" in pyproject
    base = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "httpx" not in base


def test_a_missing_httpx_gives_an_install_hint():
    code = (
        "import sys\nsys.modules['httpx'] = None\n"
        "from panoptes.cli import main\n"
        "main(['proxy', '--port', '0'])\n"
    )
    result = run(code)
    assert result.returncode == 2
    assert "panoptes-observe[proxy]" in result.stderr


def test_the_hermes_ingest_server_runs_without_the_policy_engine(tmp_path):
    result = run(
        "import sys\n"
        "from panoptes.hermes_ingest import make_server\n"
        f"server = make_server(('127.0.0.1', 0), {str(tmp_path / 'ingest.db')!r})\n"
        "server.server_close()\n"
        "bad = [m for m in ('yaml', 'httpx', 'panoptes.proxy') if m in sys.modules]\n"
        "print(bad)\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"
