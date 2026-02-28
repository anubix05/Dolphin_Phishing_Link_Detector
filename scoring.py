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
    Build the WhatsApp reply message from the list of API results.

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

    sources = "\n".join(
        f"  - {r['source']}" for r in results if r is not None
    )

    report = (
        f"🔍 *Safety Report*\n\n"
        f"*URL:* {url}\n\n"
        f"*Final Safety Score:* {final_score}%\n\n"
        f"*Classification:* {label}\n\n"
        f"*Checked using:*\n{sources}"
    )
    return report
