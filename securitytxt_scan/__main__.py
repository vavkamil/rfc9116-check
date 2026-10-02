"""Allow running the package with `python -m securitytxt_scan`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
