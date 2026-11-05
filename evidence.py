"""
Kavach - similarity evidence: why does this name look like a genuine site, letter by letter?

similarity_evidence() gives the nearest genuine domain, closeness %, edit distance, attack type,
the exact edits ("missing 'o' at position 2") and the coloured parts the UI shows side by side.
"""
import re

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein

from features import (BRANDS, CYRILLIC_LETTERS, LEGIT_DOMAINS, POPULAR_NAMES, POPULAR_SET, before_at,
                      brand_hidden_in, decode_idn, extract, is_free_hosted, is_trusted_bank, normalize,
                      parse)
from lookalikes import KEYBOARD

ATTACK_LABELS = {
    "none": "None found", "at_trick": "@ trick (hidden address)", "missing_letter": "Missing letter",
    "extra_letter": "Extra letter", "swapped_letters": "Swapped letters", "keyboard_neighbour": "Neighbouring key",
    "changed_letter": "Changed letter", "homoglyph": "Fake letters (homoglyph)", "cyrillic": "Cyrillic letters",
    "hyphen": "Hyphen inserted", "combosquat": "Combosquatting", "tld_swap": "Different ending",
    "subdomain_abuse": "Brand in subdomain", "similar_name": "Similar name",
}

# Characters that look like a real letter: shown -> the letters it can imitate
LOOKS_LIKE = {"0": "o", "1": "li", "3": "e", "5": "s", "@": "a", "l": "i", "i": "l",
              **{cyr: latin for cyr, latin in CYRILLIC_LETTERS.items()}}
LOOKS_LIKE_TWO = {"rn": "m", "vv": "w"}  # two characters that together imitate one letter

# Every name we can compare against: brands first, so a brand wins a tie
_KNOWN = {**{brand: domains[0] for brand, domains in BRANDS.items()},
          **{name: domain for name, domain in POPULAR_NAMES.items() if name not in BRANDS}}
_KNOWN_NAMES = list(_KNOWN)
_BRAND_OF_DOMAIN = {domains[0]: brand for brand, domains in BRANDS.items()}


def align(shown: str, real: str) -> list:
    """Line up two names and return the steps that turn the real one into the shown one.

    Each step is (kind, shown text, real text, position). Kinds: same, fake, replace, extra,
    missing, swap, hyphen. It is an edit-distance table, except that fake letters and hyphens
    cost almost nothing, so paytrn lines up as "rn replaces m" rather than as two separate typos.
    """
    n, m = len(shown), len(real)
    cost = [[0.0] * (m + 1) for _ in range(n + 1)]
    step = [[None] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        for j in range(m + 1):
            if i == 0 and j == 0:
                continue
            options = []
            if i and j:
                a, b = shown[i - 1], real[j - 1]
                if a == b:
                    options.append((cost[i - 1][j - 1], "same", 1, 1))
                elif b in LOOKS_LIKE.get(a, ""):
                    options.append((cost[i - 1][j - 1] + 0.1, "fake", 1, 1))
                else:
                    options.append((cost[i - 1][j - 1] + 1, "replace", 1, 1))
            if i >= 2 and j and LOOKS_LIKE_TWO.get(shown[i - 2:i]) == real[j - 1]:
                options.append((cost[i - 2][j - 1] + 0.1, "fake", 2, 1))
            if i >= 2 and j >= 2 and shown[i - 2:i] == real[j - 2:j][::-1] and shown[i - 1] != shown[i - 2]:
                options.append((cost[i - 2][j - 2] + 0.15, "swap", 2, 2))
            if i:
                extra_cost = 0.05 if shown[i - 1] == "-" else 1
                options.append((cost[i - 1][j] + extra_cost, "hyphen" if shown[i - 1] == "-" else "extra", 1, 0))
            if j:
                options.append((cost[i][j - 1] + 1, "missing", 0, 1))
            best = min(options, key=lambda o: o[0])
            cost[i][j], step[i][j] = best[0], best[1:]

    steps = []
    i, j = n, m
    while i or j:
        kind, di, dj = step[i][j]
        steps.append((kind, shown[i - di:i], real[j - dj:j], j - dj + 1))
        i, j = i - di, j - dj
    return steps[::-1]


def _steps_with_extras(text: str, real: str) -> list:
    """Like align(), but if the real name sits whole inside the text (startamazonstore), keep it
    in one piece and treat everything around it as one block of extra text."""
    if real in normalize(text).replace("-", "") and text != real:
        for start in range(len(text)):
            for end in range(start + 1, len(text) + 1):
                if normalize(text[start:end]).replace("-", "") == real:
                    before = [("extra", text[:start], "", 1)] if text[:start] else []
                    after = [("extra", text[end:], "", len(real) + 1)] if text[end:] else []
                    return before + align(text[start:end], real) + after
    return align(text, real)


def describe(step: tuple) -> str:
    """One step in plain English, or "" if nothing changed there."""
    kind, shown, real, pos = step
    if kind == "fake":
        if shown in CYRILLIC_LETTERS:
            return f"Cyrillic '{shown}' replaces '{real}' at position {pos}"
        return f"'{shown}' replaces '{real}' at position {pos}"
    if kind == "replace":
        near = " (neighbouring key)" if shown in KEYBOARD.get(real, "") else ""
        return f"'{shown}' replaces '{real}' at position {pos}{near}"
    if kind == "missing":
        return f"missing '{real}' at position {pos}"
    if kind == "swap":
        return f"'{real}' swapped to '{shown}' at position {pos}"
    if kind == "hyphen":
        return f"hyphen added before position {pos}"
    if kind == "extra":
        return f"extra text '{shown}' added" if len(shown) > 1 else f"extra '{shown}' before position {pos}"
    return ""


def _edit_lines(text: str, real: str, steps: list) -> list:
    """The edits in plain English. If the real name is whole inside a longer one (startamazonstore),
    the extra text becomes one line naming the extra words."""
    is_whole = real in normalize(text).replace("-", "")
    lines, extra_words = [], []
    for step in steps:
        if is_whole and step[0] == "extra" and len(step[1]) > 1:
            extra_words += [word for word in re.split(r"[-.]", step[1]) if word]
        elif describe(step):
            lines.append(describe(step))
    if extra_words:
        quoted = [f"'{word}'" for word in extra_words]
        listed = " and ".join(quoted) if len(quoted) <= 2 else ", ".join(quoted[:-1]) + f" and {quoted[-1]}"
        has_fakes = any(step[0] == "fake" for step in steps)
        brand = f"the brand name '{real}' (with fake letters)" if has_fakes else f"the full brand name '{real}'"
        lines.insert(0, f"Contains {brand} plus extra word{'s' if len(quoted) > 1 else ''} {listed}")
    return lines


def edits_between(name: str, real: str) -> list:
    """The exact edits from a real name to a look-alike, e.g. ["'rn' replaces 'm' at position 5"]."""
    return [text for text in map(describe, _steps_with_extras(decode_idn(name), real)) if text]


def _parts_from_steps(steps: list) -> tuple:
    """Turn steps into two lists of (text, colour kind) for the side-by-side box."""
    shown_parts, real_parts = [], []
    for kind, shown, real, _ in steps:
        if kind == "same":
            shown_parts.append((shown, "same"))
            real_parts.append((real, "same"))
        elif kind == "missing":
            shown_parts.append((real, "missing"))
            real_parts.append((real, "same"))
        else:
            shown_parts.append((shown, "changed"))
            if real:
                real_parts.append((real, "changed"))
    return shown_parts, real_parts


def _distance(text: str, real: str) -> int:
    """Edit distance after fixing fake letters and removing hyphens."""
    clean = normalize(text).replace("-", "")
    one_as_i = normalize(text.replace("1", "i")).replace("-", "")
    return min(DamerauLevenshtein.distance(clean, real), DamerauLevenshtein.distance(one_as_i, real))


def _closeness(text: str, real: str) -> int:
    """0-100: how similar the whole name is, from Damerau-Levenshtein after fixing fake letters.
    A brand copied inside a longer name scores low here: that is reported as combosquatting instead."""
    clean = normalize(text).replace("-", "")
    longest = max(len(clean), len(real), 1)
    return round(100 * (1 - _distance(text, real) / longest))


def _attack_type(text: str, real: str, steps: list) -> str:
    kinds = {step[0] for step in steps}
    if any(c in CYRILLIC_LETTERS for c in text):
        return "cyrillic"
    if text == real:
        return "tld_swap"
    if text.replace("-", "") == real:
        return "hyphen"
    if "fake" in kinds:
        return "homoglyph"
    changes = [step for step in steps if step[0] not in ("same", "hyphen")]
    is_block_of_text = len(changes) == 1 and changes[0][0] == "extra" and len(changes[0][1]) > 1
    if len(changes) == 1 and not is_block_of_text:
        kind, shown, wanted, _ = changes[0]
        if kind == "replace":
            return "keyboard_neighbour" if shown in KEYBOARD.get(wanted, "") else "changed_letter"
        return {"missing": "missing_letter", "extra": "extra_letter", "swap": "swapped_letters"}[kind]
    if real in normalize(text).replace("-", ""):
        return "combosquat"
    return "similar_name"


def _result(genuine, closeness, distance, attack, edits, shown_parts, real_parts, is_genuine=False) -> dict:
    # Only the real site itself gets 100%. Fake letters can fix up to an exact match (paytrn -> paytm)
    # and another ending doesn't change the name (reddit.xyz), so those stop at 99%.
    if not is_genuine:
        closeness = min(closeness, 99)
    return {"nearest_genuine": genuine, "closeness": closeness, "edit_distance": distance,
            "attack_type": attack, "attack_label": ATTACK_LABELS[attack], "edits": edits,
            "shown_parts": shown_parts, "real_parts": real_parts, "is_genuine": is_genuine}


def similarity_evidence(url: str, target) -> dict:
    """Everything the UI needs to show why a name looks like a genuine one.
    target is the real domain from detector.lookalike_target(), or None."""
    parts, host = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    hidden = before_at(url)
    subdomain = "" if parts.subdomain == "www" else parts.subdomain.removeprefix("www.")
    bare_host = decode_idn(host.removeprefix("www."))
    real_name = _BRAND_OF_DOMAIN.get(target, extract(target).domain) if target else None

    # 1. @ trick pretending to be a real site
    if hidden is not None and target:
        shown = hidden.split(":")[0]
        edits = [f"text before the @ is ignored: the browser goes to {bare_host}"]
        real_host_name = decode_idn(parts.domain)  # what the browser really goes to
        return _result(target, _closeness(real_host_name, real_name), _distance(real_host_name, real_name),
                       "at_trick", edits, [(shown, "same"), (f"@{bare_host}", "changed")], [(target, "same")])

    # 2. The genuine site itself
    is_real = domain in LEGIT_DOMAINS or is_trusted_bank(host) or domain in POPULAR_SET
    if hidden is None and is_real and not target and not is_free_hosted(host):
        name = bare_host if is_trusted_bank(host) else domain
        return _result(name, 100, 0, "none", [], [(bare_host, "same")], [(name, "same")], is_genuine=True)

    # 3. Pretending to be a real site
    name = decode_idn(parts.domain)
    if target:
        # Brand (or top site) name in the subdomain, while the domain's own name is unrelated
        in_subdomain = (real_name in normalize(subdomain).replace("-", "")
                        and not brand_hidden_in(parts.domain, real_name) and _closeness(name, real_name) < 80)
        if in_subdomain:
            steps = _steps_with_extras(bare_host, real_name)
            edits = [f"'{real_name}' is only a subdomain: the real domain here is {domain}"]
            shown_parts, real_parts = _parts_from_steps(steps)
            real_parts.append((target[len(real_name):], "same") if target.startswith(real_name) else (f" ({target})", "same"))
            whole_name = bare_host.removesuffix(f".{parts.suffix}").replace(".", "")
            return _result(target, _closeness(whole_name, real_name), _distance(whole_name, real_name),
                           "subdomain_abuse", edits, shown_parts, real_parts)

        steps = _steps_with_extras(name, real_name)
        shown_parts, real_parts = _parts_from_steps(steps)
        edits = _edit_lines(name, real_name, steps)
        # Add the ending, so the whole domain is compared
        real_suffix = extract(target).suffix
        if parts.suffix != real_suffix:
            edits.append(f"ending '.{parts.suffix}' instead of '.{real_suffix}'")
        same_end = parts.suffix == real_suffix
        shown_parts.append((f".{parts.suffix}", "same" if same_end else "changed"))
        real_parts.append((f".{real_suffix}", "same" if same_end else "changed"))
        attack = "at_trick" if hidden is not None else _attack_type(name, real_name, steps)
        return _result(target, _closeness(name, real_name), _distance(name, real_name), attack, edits, shown_parts, real_parts)

    # 4. Nothing imitated: still report the closest known name, compared with the whole name.
    # On a free-hosting site the name is the host's, so compare the part the owner chose.
    text = subdomain if is_free_hosted(host) else name
    clean = normalize(text).replace("-", "")
    nearest = process.extractOne(clean, _KNOWN_NAMES, scorer=DamerauLevenshtein.normalized_similarity)[0]
    distance = _distance(text, nearest)
    closeness = round(100 * (1 - distance / max(len(clean), len(nearest), 1)))
    attack = "at_trick" if hidden is not None else "none"
    edits = [f"text before the @ is ignored: the browser goes to {bare_host}"] if hidden is not None else []
    # Below 50% it is not really close to anything, so don't name a site at random
    return _result(_KNOWN[nearest] if closeness >= 50 else None, closeness, distance, attack, edits, [], [])
