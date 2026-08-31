#!/usr/bin/env python3
"""Render hardcoded OpenSRE star-history SVGs from owner-only stargazer timestamps.

GitHub no longer lets third-party services read stargazer dates. This script
is a one-shot generator: you run it locally with `gh` (collaborator access),
and it writes light/dark SVGs that the README embeds as static files.

Refresh later with:

    gh api --paginate repos/swapnildahiphale/OpenSRE/stargazers \\
      -H "Accept: application/vnd.github.star+json" \\
      --jq '.[] | .starred_at' | python3 scripts/render_star_history.py
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / ".github" / "assets"

# Flow-ui / opensre.in tokens (slate + emerald). GitHub strips @font-face
# from README <img> SVGs, so we stick to the system UI stack.
WIDTH = 800
HEIGHT = 320
PAD_L = 56
PAD_R = 36
PAD_T = 68
PAD_B = 44
FONT = "ui-sans-serif, system-ui, -apple-system, sans-serif"

THEMES = {
    "light": {
        "bg": "#ffffff",
        "grid": "#e2e8f0",
        "axis": "#94a3b8",
        "muted": "#64748b",
        "ink": "#0f172a",
        "line": "#059669",
        "fill": "#10b981",
        "dot_ring": "#d1fae5",
    },
    "dark": {
        "bg": "#0f172a",
        "grid": "#1e293b",
        "axis": "#475569",
        "muted": "#94a3b8",
        "ink": "#f8fafc",
        "line": "#34d399",
        "fill": "#34d399",
        "dot_ring": "#064e3b",
    },
}


def parse_dates(lines: list[str]) -> list[date]:
    """Parse ISO timestamps into UTC calendar dates, sorted."""
    out: list[date] = []
    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        # GitHub returns ...Z; fromisoformat needs +00:00 before 3.11 on some builds.
        text = text.replace("Z", "+00:00")
        out.append(datetime.fromisoformat(text).astimezone(timezone.utc).date())
    if not out:
        raise SystemExit("no starred_at timestamps on stdin")
    return sorted(out)


def series(star_days: list[date], until: date) -> list[tuple[date, int]]:
    """Cumulative count on each day a star arrived, plus a flat hold to `until`."""
    points: list[tuple[date, int]] = []
    count = 0
    current: date | None = None
    for day in star_days:
        count += 1
        if current == day:
            points[-1] = (day, count)
        else:
            points.append((day, count))
            current = day
    if points[-1][0] < until:
        points.append((until, count))
    return points


def nice_ymax(n: int) -> int:
    """Round the y-axis above n to a readable tick (40/80/120…)."""
    if n <= 40:
        return 40
    step = 40 if n <= 200 else 100
    return ((n + step - 1) // step) * step


def month_ticks(start: date, end: date) -> list[date]:
    """Label the start date, then the first of each later month in range."""
    ticks: list[date] = [start]
    y, m = start.year, start.month
    m += 1
    if m > 12:
        y, m = y + 1, 1
    cursor = date(y, m, 1)
    while cursor <= end:
        ticks.append(cursor)
        m += 1
        if m > 12:
            y, m = y + 1, 1
        cursor = date(y, m, 1)
    return ticks


def xy(
    day: date,
    count: int,
    start: date,
    end: date,
    ymax: int,
) -> tuple[float, float]:
    span = max((end - start).days, 1)
    plot_w = WIDTH - PAD_L - PAD_R
    plot_h = HEIGHT - PAD_T - PAD_B
    x = PAD_L + plot_w * ((day - start).days / span)
    y = PAD_T + plot_h * (1 - count / ymax)
    return x, y


def polyline(points: list[tuple[date, int]], start: date, end: date, ymax: int) -> str:
    cmds: list[str] = []
    for i, (day, count) in enumerate(points):
        x, y = xy(day, count, start, end, ymax)
        cmds.append(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}")
    return " ".join(cmds)


def render(theme_name: str, points: list[tuple[date, int]], snapshot: date) -> str:
    theme = THEMES[theme_name]
    start, end = points[0][0], points[-1][0]
    total = points[-1][1]
    ymax = nice_ymax(total)
    line = polyline(points, start, end, ymax)
    last_x, last_y = xy(end, total, start, end, ymax)
    base_y = HEIGHT - PAD_B
    first_x, _ = xy(start, points[0][1], start, end, ymax)
    area = f"{line} L{last_x:.1f},{base_y:.1f} L{first_x:.1f},{base_y:.1f} Z"

    y_ticks = list(range(0, ymax + 1, ymax // 4 if ymax >= 4 else 1))
    grid: list[str] = []
    for tick in y_ticks:
        _, gy = xy(start, tick, start, end, ymax)
        grid.append(
            f'<line x1="{PAD_L}" y1="{gy:.1f}" x2="{WIDTH - PAD_R}" y2="{gy:.1f}" '
            f'stroke="{theme["grid"]}" stroke-width="1"/>'
            f'<text x="{PAD_L - 10}" y="{gy:.1f}" fill="{theme["axis"]}" '
            f'font-size="11" text-anchor="end" dominant-baseline="middle">{tick}</text>'
        )

    x_labels: list[str] = []
    for tick in month_ticks(start, end):
        tx, _ = xy(tick, 0, start, end, ymax)
        label = tick.strftime("%b")
        x_labels.append(
            f'<text x="{tx:.1f}" y="{HEIGHT - 16}" fill="{theme["axis"]}" '
            f'font-size="11" text-anchor="middle">{label}</text>'
        )

    gid = f"fill-{theme_name}"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="OpenSRE GitHub star history, {total} stars as of {snapshot.isoformat()}">
  <title>OpenSRE star history</title>
  <rect width="100%" height="100%" fill="{theme["bg"]}"/>
  <text x="{PAD_L}" y="24" fill="{theme["muted"]}" font-family="{FONT}" font-size="12">Star history</text>
  <text x="{PAD_L}" y="44" fill="{theme["ink"]}" font-family="{FONT}" font-size="22" font-weight="600">{total} stars</text>
  <text x="{WIDTH - PAD_R}" y="44" fill="{theme["muted"]}" font-family="{FONT}" font-size="12" text-anchor="end">as of {snapshot.day} {snapshot.strftime("%b %Y")}</text>
  <g font-family="{FONT}">
    {"".join(grid)}
    {"".join(x_labels)}
  </g>
  <defs>
    <linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="{theme["fill"]}" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="{theme["fill"]}" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <path d="{area}" fill="url(#{gid})"/>
  <path d="{line}" fill="none" stroke="{theme["line"]}" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="7" fill="{theme["dot_ring"]}"/>
  <circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="4" fill="{theme["line"]}"/>
</svg>
"""


def main() -> None:
    lines = sys.stdin.read().splitlines()
    star_days = parse_dates(lines)
    snapshot = datetime.now(timezone.utc).date()
    points = series(star_days, until=snapshot)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("light", "dark"):
        path = OUT_DIR / f"star-history-{name}.svg"
        path.write_text(render(name, points, snapshot), encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)} ({points[-1][1]} stars)")


if __name__ == "__main__":
    main()
