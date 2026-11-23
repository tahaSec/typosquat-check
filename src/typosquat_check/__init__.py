"""typosquat-check - catch typosquatted and hallucinated package names."""

__version__ = "0.1.0"

from .detect import Finding, check_name  # noqa: E402

__all__ = ["check_name", "Finding", "__version__"]
