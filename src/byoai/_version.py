"""Single source of truth for the package version.

pyproject.toml reads ``__version__`` at build time via hatchling's
``[tool.hatch.version]``; runtime code imports it from here (not from the
package root, so low-level modules can use it without circular imports).
"""

__version__ = "0.1.0"

USER_AGENT = f"byoai-runtime/{__version__}"
