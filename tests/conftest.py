"""Make the integration's HA-free modules importable as a package without
running custom_components/security_logger/__init__.py (which imports Home
Assistant, not installed in the test env).

We register a bare `security_logger` package pointing at the component dir, so
`import security_logger.storage` / `.anomaly` / `.history` resolve their
relative imports against it, but the package __init__ never executes.

Works whether the tests are run under pytest (auto-loads conftest) or directly
as scripts (imported at the top of each test module).
"""
import os
import sys
import types

_COMPONENT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "custom_components", "security_logger"
    )
)

if "security_logger" not in sys.modules:
    _pkg = types.ModuleType("security_logger")
    _pkg.__path__ = [_COMPONENT_DIR]
    sys.modules["security_logger"] = _pkg
