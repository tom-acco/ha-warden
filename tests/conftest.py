"""Make the integration's HA-free modules importable as a package without
running custom_components/warden/__init__.py (which imports Home
Assistant, not installed in the test env).

We register a bare `warden` package pointing at the component dir, so
`import warden.storage` / `.anomaly` / `.history` resolve their
relative imports against it, but the package __init__ never executes.

Works whether the tests are run under pytest (auto-loads conftest) or directly
as scripts (imported at the top of each test module).
"""
import os
import sys
import types

_COMPONENT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "custom_components", "warden"
    )
)

if "warden" not in sys.modules:
    _pkg = types.ModuleType("warden")
    _pkg.__path__ = [_COMPONENT_DIR]
    sys.modules["warden"] = _pkg
