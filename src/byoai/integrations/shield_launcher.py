"""The `byoai-shield` command: starts Shield, or says how to install what it lacks.

Shield signs its record with `cryptography`, which a plain install of
byoai-runtime does not bring in. Importing `byoai.integrations.shield` without
it raises a normal ModuleNotFoundError (right for a library); this launcher is
the one place that turns it into an instruction instead of a traceback.
"""
from __future__ import annotations

import sys

INSTALL_HINT = (
    "Shield signs its record with the 'cryptography' package, which is not installed.\n"
    'Install it with:  pip install "byoai-runtime[shield]"'
)


def main() -> None:
    try:
        from byoai.integrations.shield import main as run
    except ModuleNotFoundError as exc:
        if (exc.name or "").split(".")[0] != "cryptography":
            raise                       # anything else is a real bug: keep the traceback
        print(INSTALL_HINT, file=sys.stderr)
        raise SystemExit(1) from None
    run()


if __name__ == "__main__":
    main()
