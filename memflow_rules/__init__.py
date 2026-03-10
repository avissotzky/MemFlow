# memflow_rules – External JSON rule-sets for MemFlow alert modules.
#
# Each JSON file defines analyst-tunable detection constants (whitelists,
# blacklists, regex patterns, parent-child rules, etc.) so they can be
# edited without touching Python code.
#
# Usage:
#     from memflow_rules import load_ruleset
#     _rules = load_ruleset("network")   # loads network.json once, caches it

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

_RULES_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load_ruleset(name: str) -> Dict[str, Any]:
    """Load and cache a JSON ruleset by name (without ``.json`` extension).

    Parameters
    ----------
    name:
        Base name of the JSON file, e.g. ``"network"`` for ``network.json``.

    Returns
    -------
    dict
        Raw parsed JSON dictionary.  Callers are responsible for converting
        values to the required Python types (``set``, ``re.Pattern``, etc.).

    Raises
    ------
    FileNotFoundError
        If the requested JSON file does not exist in the rules directory.
    """
    path = _RULES_DIR / f"{name}.json"
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
