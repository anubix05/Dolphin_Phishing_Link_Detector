from config import SCORE_UNSAFE_MAX, SCORE_CAUTION_MAX


def calculate_final_score(results: list[dict]) -> float:
    """
    Average the normalized scores returned by each API module.

    Parameters
    ----------
    results : list of dicts with keys 'score' (0-100) and 'source' (str)

    Returns
    -------
    float  –  averaged score rounded to 2 decimal places, or 0.0 if empty
    """
    valid = [r for r in results if r is not None and "score" in r]
    if not valid:
        return 0.0
    total = sum(r["score"] for r in valid)
    return round(total / len(valid), 2)


def classify(score: float) -> str:
    """
    Map a numeric score to a human-readable safety classification.

    | Range   | Classification          |
    |---------|-------------------------|
    | 0 – 33  | UNSAFE                  |
    | 34 – 66 | CAUTION                 |
    | 67 – 100| SAFE                    |
    """
    if score <= SCORE_UNSAFE_MAX:
        return "UNSAFE"
    elif score <= SCORE_CAUTION_MAX:
        return "CAUTION"
    else:
        return "SAFE"


def build_report(url: str, results: list[dict]) -> str:
    """
    Build the reply message from the list of API results.

    Parameters
    ----------
    url     : the original URL that was checked
    results : list of dicts returned by the API modules

    Returns
    -------
    str  –  formatted safety report
    """
    final_score = calculate_final_score(results)
    classification = classify(final_score)

    if classification == "SAFE":
        label = "SAFE ✅"
    elif classification == "CAUTION":
        label = "AVERAGE / USE CAUTION ⚠️"
    else:
        label = "UNSAFE ❌"

    # ── Per-source score breakdown ────────────────────────────────────────────
    sources = "\n".join(
        f"  - {r['source']}: {r['score']}%" for r in results if r is not None
    )

    # ── Heuristic flags section (only when flags were raised) ─────────────────
    heuristic_section = ""
    heuristic_result = next(
        (r for r in results if r is not None and r.get("source") == "Heuristics"),
        None,
    )
    if heuristic_result:
        flags = heuristic_result.get("flags", [])
        if flags:
            flag_lines = "\n".join(
                f"  ⚑ {f['name']}: {f['description']}"
                for f in flags
            )
            heuristic_section = f"\n\n*🧠 Heuristic Red Flags ({len(flags)} detected):*\n{flag_lines}"
        else:
            heuristic_section = "\n\n*🧠 Heuristics:* No structural red flags detected ✅"

    report = (
        f"🔍 *Safety Report*\n\n"
        f"*URL:* {url}\n\n"
        f"*Final Safety Score:* {final_score}%\n\n"
        f"*Classification:* {label}\n\n"
        f"*Score by source:*\n{sources}"
        f"{heuristic_section}"
    )
    return report
