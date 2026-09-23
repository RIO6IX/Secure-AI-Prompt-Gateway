from __future__ import annotations

import re
from datetime import date

MONTHS = {
    name: index
    for index, names in enumerate(
        (
            ("jan", "january"), ("feb", "february"), ("mar", "march"), ("apr", "april"),
            ("may",), ("jun", "june"), ("jul", "july"), ("aug", "august"),
            ("sep", "sept", "september"), ("oct", "october"), ("nov", "november"), ("dec", "december"),
        ),
        start=1,
    )
    for name in names
}
ISO_RE = re.compile(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$")
DMY_RE = re.compile(r"^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$")
TEXT_RE = re.compile(r"^(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})$")
MAX_AGE_YEARS = 120


def parse_birth_date(value: str) -> date | None:
    text = value.strip()
    try:
        if match := ISO_RE.fullmatch(text):
            year, month, day = (int(part) for part in match.groups())
        elif match := DMY_RE.fullmatch(text):
            # Sri Lanka and most of the world write day/month/year.
            day, month, year = (int(part) for part in match.groups())
        elif match := TEXT_RE.fullmatch(text):
            month = MONTHS.get(match.group(2).lower())
            if month is None:
                return None
            day, year = int(match.group(1)), int(match.group(3))
        else:
            return None
        return date(year, month, day)
    except ValueError:
        return None


def is_plausible_birth_date(value: str) -> bool:
    born = parse_birth_date(value)
    if born is None:
        return False
    today = date.today()
    return born <= today and today.year - born.year <= MAX_AGE_YEARS
