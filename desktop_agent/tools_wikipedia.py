"""
Wikipedia lookup: search and read encyclopedia articles.

  searchWikipedia -> find article titles matching a query (returns summaries).
  readWikipedia   -> fetch the full (sectioned) text of a specific article.
  wikipediaSummary-> a concise first-paragraph summary of a topic.

Backed by the Wikipedia-API library (https://pypi.org/project/Wikipedia-API/),
which queries the official MediaWiki API — no scraping, no browser needed.

A configurable contact email is sent in the User-Agent per Wikipedia's API
etiquette policy. If Wikipedia-API is not installed, the tools degrade
gracefully with a clear "install Wikipedia-API" message instead of crashing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .registry import ToolError, register

# Per Wikipedia's API etiquette policy, a contact address should accompany
# automated requests. Override with the WIKIPEDIA_CONTACT env var if desired.
import os

_CONTACT_EMAIL = os.environ.get("WIKIPEDIA_CONTACT", "yashi-agent@example.com")
_USER_AGENT = f"YashiDesktopAgent/1.0 ({_CONTACT_EMAIL})"

# Module-level client (lazy-initialized). Wikipedia-API's Wikipedia class is
# safe to reuse across requests.
_wiki = None


def _get_wiki():
    """Lazily build the Wikipedia-API client. Returns None if unavailable."""
    global _wiki
    if _wiki is not None:
        return _wiki
    try:
        import wikipediaapi  # type: ignore
    except ImportError:
        return None
    _wiki = wikipediaapi.Wikipedia(
        user_agent=_USER_AGENT,
        language="en",
        extract_format=wikipediaapi.ExtractFormat.WIKI,
    )
    return _wiki


def _require_wiki():
    """Return the client or raise a clean, user-facing ToolError."""
    wiki = _get_wiki()
    if wiki is None:
        raise ToolError(
            "Wikipedia lookup is unavailable: the 'Wikipedia-API' package is "
            "not installed. Install it with: pip install Wikipedia-API"
        )
    return wiki


def _summarize_page(page, max_chars: int) -> Dict[str, Any]:
    """Turn a Wikipedia-API Page into a compact dict."""
    title = getattr(page, "title", "")
    if hasattr(page, "summary") and page.summary:
        summary = page.summary
    else:
        # Fallback: first N chars of the text.
        text = page.text or ""
        summary = text[:max_chars]
    if len(summary) > max_chars:
        summary = summary[:max_chars].rstrip() + "…"
    return {
        "title": title,
        "summary": summary,
        "url": getattr(page, "fullurl", "") or f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}",
    }


@register("searchWikipedia")
def search_wikipedia(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search Wikipedia for article titles matching a query.

    Returns up to `limit` (default 5) matches, each with a short summary so the
    model can decide which article to read in full.
    """
    query = args.get("query") or args.get("q") or args.get("term")
    if not query:
        raise ToolError("Parameter 'query' is required.")
    limit = int(args.get("limit", 5))
    max_chars = int(args.get("max_chars", 300))
    wiki = _require_wiki()

    # Wikipedia-API has no native search; use its underlying MediaWiki search
    # via the `opensearch`-style approach. We fall back to fetching the page
    # directly by title, then try the library's built-in search if present.
    results: List[Dict[str, Any]] = []

    # Strategy 1: try the exact/near-exact page by query (most common path).
    page = wiki.page(str(query))
    if page and getattr(page, "exists", False):
        results.append(_summarize_page(page, max_chars))

    # Strategy 2: use the library's search method if the installed version
    # exposes one (newer Wikipedia-API versions do).
    if len(results) < limit:
        search_fn = getattr(wiki, "search", None)
        if callable(search_fn):
            try:
                hits = search_fn(str(query), results=limit) or []
                for hit in hits:
                    title = hit if isinstance(hit, str) else getattr(hit, "title", "")
                    if not title or any(r["title"] == title for r in results):
                        continue
                    p = wiki.page(title)
                    if p and getattr(p, "exists", False):
                        results.append(_summarize_page(p, max_chars))
                    if len(results) >= limit:
                        break
            except Exception:
                # Search isn't critical; the exact-title path above covers the
                # common case. Continue with whatever we have.
                pass

    if not results:
        return {
            "result": f"No Wikipedia articles found for '{query}'.",
            "results": [],
            "count": 0,
        }

    return {
        "result": f"Found {len(results)} Wikipedia article(s) for '{query}'.",
        "results": results,
        "count": len(results),
    }


@register("readWikipedia")
def read_wikipedia(args: Dict[str, Any]) -> Dict[str, Any]:
    """Read the full text of a Wikipedia article by title.

    The text is returned in MediaWiki-style sections (== Section ==) and
    trimmed to `max_chars` (default 6000) to stay model-friendly.
    """
    title = args.get("title") or args.get("query") or args.get("topic")
    if not title:
        raise ToolError("Parameter 'title' (article title) is required.")
    max_chars = int(args.get("max_chars", 6000))
    wiki = _require_wiki()

    page = wiki.page(str(title))
    if not page or not getattr(page, "exists", False):
        # Suggest a correction if the library provides one.
        raise ToolError(
            f"No Wikipedia article titled '{title}'. Check the spelling or use "
            f"searchWikipedia to find the exact title first."
        )

    full_text = page.text or ""
    if len(full_text) > max_chars:
        full_text = full_text[:max_chars].rstrip() + f"\n…[truncated, {len(page.text) - max_chars} more chars]"

    return {
        "result": f"Read Wikipedia article: {page.title}.",
        "title": page.title,
        "url": getattr(page, "fullurl", "") or f"https://en.wikipedia.org/wiki/{page.title.replace(' ', '_')}",
        "text": full_text,
    }


@register("wikipediaSummary")
def wikipedia_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get a concise first-paragraph summary of a Wikipedia topic.

    Lighter than readWikipedia — ideal for quick 'who/what is X?' lookups.
    """
    title = args.get("title") or args.get("query") or args.get("topic")
    if not title:
        raise ToolError("Parameter 'title' is required.")
    max_chars = int(args.get("max_chars", 600))
    wiki = _require_wiki()

    page = wiki.page(str(title))
    if not page or not getattr(page, "exists", False):
        raise ToolError(f"No Wikipedia article found for '{title}'.")

    summary = page.summary or ""
    if len(summary) > max_chars:
        summary = summary[:max_chars].rstrip() + "…"
    return {
        "result": f"Wikipedia summary for {page.title}.",
        "title": page.title,
        "summary": summary,
        "url": getattr(page, "fullurl", "") or f"https://en.wikipedia.org/wiki/{page.title.replace(' ', '_')}",
    }


__all__ = ["search_wikipedia", "read_wikipedia", "wikipedia_summary"]
