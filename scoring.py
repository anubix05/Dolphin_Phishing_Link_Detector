from config import SCORE_UNSAFE_MAX, SCORE_CAUTION_MAX, SOURCE_WEIGHTS


def calculate_final_score(results: list[dict]) -> float:
    """
    Weighted average of the normalized scores returned by each API module.

    Each source has a priority weight defined in config.SOURCE_WEIGHTS.
    Sources with higher weight contribute more to the final score.
    Unknown sources default to weight 1.

    Parameters
    ----------
    results : list of dicts with keys 'score' (0-100) and 'source' (str)

    Returns
    -------
    float  –  weighted score rounded to 2 decimal places, or 0.0 if empty
    """
    valid = [r for r in results if r is not None and "score" in r]
    if not valid:
        return 0.0
    weighted_total = sum(
        r["score"] * SOURCE_WEIGHTS.get(r.get("source", ""), 1)
        for r in valid
    )
    weight_sum = sum(
        SOURCE_WEIGHTS.get(r.get("source", ""), 1)
        for r in valid
    )
    return round(weighted_total / weight_sum, 2)


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

    # ── Per-source score breakdown (sorted by priority weight) ─────────────
    sorted_results = sorted(
        [r for r in results if r is not None],
        key=lambda r: SOURCE_WEIGHTS.get(r.get("source", ""), 1),
        reverse=True,
    )
    def _format_source_line(r: dict) -> str:
        line = f"  - {r['source']}: {r['score']}%"
        if r.get("source") == "Google Safe Browsing" and r.get("score") == 0:
            line += "  ⛔ UNSAFE – threat detected by Google"
        return line

    sources = "\n".join(_format_source_line(r) for r in sorted_results)

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
