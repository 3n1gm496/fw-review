"""HTML writer for drift summaries."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def write_compare_summary_html(path: Path, drift: dict[str, Any]) -> Path:
    """Render a static HTML summary for drift results."""
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("drift_summary.html.j2")
    html = template.render(generated_at=datetime.now(UTC), drift=drift)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
