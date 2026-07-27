"""
Sanctions / AML screening (R6).

The compliance piece the roadmap names after Sumsub. What this is, stated
plainly, because a screening module that overstates itself is worse than none:

  * It screens against a list YOU supply. There is no list bundled and none is
    fetched. `SANCTIONS_LIST_PATH` points at a JSON file of entries; unset
    means the screening layer reports `not_configured` and screens nothing.
  * A name match is a SIGNAL, not a finding. Ethiopian naming — given name plus
    father's name, with many transliterations of the same name — makes exact
    string matching both lossy and noisy. A hit here means "a human must look",
    never "this person is sanctioned".
  * Nothing here blocks anything. Screening writes a record and surfaces it to
    an operator. Automatically refusing a national-ID-verified person a wallet
    binding on a fuzzy name match is a decision with legal weight that this
    codebase has no authority to make.

The real thing needs a licensed list (OFAC SDN, UN Consolidated, EU), a
transliteration-aware matcher, and a documented adjudication process. This is
the seam that accepts one, plus the honest interim: an operator-visible check
whose limits are legible from its output.
"""

import json
import os
import re
import threading
import unicodedata
from pathlib import Path

LIST_PATH = os.getenv("SANCTIONS_LIST_PATH", "").strip()

_LOCK = threading.Lock()
_ENTRIES: list[dict] | None = None
_LOADED_FROM: str | None = None


def _normalise(name: str) -> str:
    """
    Fold to a comparable form: strip accents, punctuation and case, collapse
    whitespace. Deliberately NOT a transliteration engine — Amharic script and
    its many Latin renderings ("Tesfaye"/"Tesfaie"/"Tesfay") are exactly what a
    real matcher handles and this does not, which is the main reason its output
    is a signal rather than a verdict.
    """
    folded = unicodedata.normalize("NFKD", name or "")
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    folded = re.sub(r"[^\w\s]", " ", folded.lower())
    return " ".join(folded.split())


def _load() -> list[dict]:
    global _ENTRIES, _LOADED_FROM
    with _LOCK:
        if _ENTRIES is not None and _LOADED_FROM == LIST_PATH:
            return _ENTRIES
        entries: list[dict] = []
        if LIST_PATH and Path(LIST_PATH).is_file():
            try:
                raw = json.loads(Path(LIST_PATH).read_text())
                for item in raw if isinstance(raw, list) else []:
                    if not isinstance(item, dict) or not item.get("name"):
                        continue
                    entries.append({
                        "name": str(item["name"])[:200],
                        "list": str(item.get("list", "unknown"))[:64],
                        "reference": str(item.get("reference", ""))[:64],
                        "_norm": _normalise(str(item["name"])),
                    })
            except Exception:
                # A malformed list must not take the app down, and must not
                # silently look like a clean list either — configured() stays
                # true while entries are empty, and screen() reports the count.
                entries = []
        _ENTRIES, _LOADED_FROM = entries, LIST_PATH
        return entries


def configured() -> bool:
    return bool(LIST_PATH)


def screen(display_name: str) -> dict:
    """
    Screen one name. Never raises, never blocks, never decides.

    Returns `status` ('not_configured' | 'screened'), the matches found, and
    `list_size` so an operator can tell "no hits against 40,000 entries" from
    "no hits because the list failed to parse" — the same distinction the
    on-chain panel draws between "no transactions" and "we did not look".
    """
    if not configured():
        return {"status": "not_configured", "matches": [], "list_size": 0,
                "detail": "SANCTIONS_LIST_PATH is unset — no screening was performed"}
    entries = _load()
    needle = _normalise(display_name)
    matches = []
    if needle:
        needle_parts = set(needle.split())
        for e in entries:
            entry_parts = set(e["_norm"].split())
            if e["_norm"] == needle:
                confidence = "exact"
            elif needle_parts and (needle_parts <= entry_parts
                                   or entry_parts <= needle_parts):
                # Subset in EITHER direction. One-way containment produced the
                # exact false-clean this module exists to avoid: a three-part
                # Fayda name ("Tesfaye Bekele Alemu") against a two-part list
                # entry ("Tesfaye Bekele") returned no hits and reported
                # `screened`, which reads as cleared. Ethiopian names are given
                # name plus father's name, often with a grandfather's name
                # appended or omitted depending on the document, so the two
                # sides routinely differ in length for the same person.
                confidence = "partial"
            else:
                continue
            matches.append({"name": e["name"], "list": e["list"],
                            "reference": e["reference"], "confidence": confidence})
            if len(matches) >= 25:
                break
    return {
        "status": "screened",
        "matches": matches,
        "list_size": len(entries),
        "detail": ("name-only match against a supplied list; a hit requires "
                   "human adjudication and is not a determination"),
    }


def reset() -> None:
    """Test seam."""
    global _ENTRIES, _LOADED_FROM
    with _LOCK:
        _ENTRIES, _LOADED_FROM = None, None
