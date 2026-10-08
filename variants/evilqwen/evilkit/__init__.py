"""evilkit — a scope-gated launcher for the Qwen 3.6 Plus Uncensored brain."""

__version__ = "1.0.0"

#: The hosted brain this version is built around. The matching launcher reads
#: these so the checkout and the launcher cannot disagree about the model.
BRAIN_NAME = "qwen-3.6-plus"
BRAIN_MODEL = "venice-uncensored-1-2"
BRAIN_URL = "https://api.venice.ai/v1"

__all__ = ["__version__", "BRAIN_NAME", "BRAIN_MODEL", "BRAIN_URL"]
