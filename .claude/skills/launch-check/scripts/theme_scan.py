#!/usr/bin/env python3
"""Static pre-launch scan of a Shopify theme repo.

Looks for security problems (secrets, unescaped output, risky DOM writes, insecure URLs), leftover
placeholder/demo content, and Shopify-specific gotchas. Heuristic by design: every finding names the
file and line so a human (or Claude) can confirm it before acting.

Usage: python3 theme_scan.py [theme_root] [--json]
"""
import json
import re
import sys
from pathlib import Path

THEME_DIRS = ["assets", "blocks", "config", "layout", "locales", "sections", "snippets", "templates"]
TEXT_EXT = {".liquid", ".json", ".js", ".css", ".svg"}
SEVERITY_ORDER = {"blocker": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

findings = []


def add(severity, category, path, line, message, snippet=""):
    findings.append({
        "severity": severity,
        "category": category,
        "file": str(path),
        "line": line,
        "message": message,
        "snippet": snippet.strip()[:160],
    })


def iter_files(root):
    for d in THEME_DIRS:
        base = root / d
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and p.suffix in TEXT_EXT and not p.name.endswith(".min.js"):
                yield p


def line_of(text, index):
    return text.count("\n", 0, index) + 1


# --- patterns -------------------------------------------------------------------------------------

SECRET_PATTERNS = [
    (re.compile(r"shp(at|ca|pa|ss)_[0-9a-fA-F]{20,}"), "Shopify access token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{16,}"), "Stripe live secret key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"(?i)(api[_-]?key|secret|access[_-]?token|password)['\"]?\s*[:=]\s*['\"](?=[^'\" ]*\d)(?=[^'\" ]*[A-Za-z])[^'\" ]{10,}['\"]"),
     "Hard-coded credential"),
]

# Liquid output that reflects visitor-controlled input. Shopify already HTML-escapes search.terms, form.errors and
# request.path (verified on a live store: a search for "><i>x</i> renders as &quot;&amp;gt;x), so those are
# reported as info; customer-entered profile fields are not guaranteed to be escaped.
VISITOR_INPUT = re.compile(r"\{\{[^}]*(?<![\w.'])(search\.terms|request\.(path|host|page_type)|form\.errors|customer\.(email|first_name|last_name|name))[^}]*\}\}")
PLATFORM_ESCAPED = re.compile(r"search\.terms|request\.(path|host|page_type)|form\.errors")
ESCAPED = re.compile(r"\|\s*(escape|json|url_encode|url_escape|strip_html|handle|money|date)")

SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
JS_LIQUID_BLOCK = re.compile(r"\{%-?\s*javascript\s*-?%\}(.*?)\{%-?\s*endjavascript\s*-?%\}", re.S)
LIQUID_OUTPUT = re.compile(r"\{\{-?(.*?)-?\}\}", re.S)
TEXTY_LIQUID = re.compile(r"(\.title|\.name|\.description|\.content|\.text|\.label|\.heading|\.alt|block\.settings\.|section\.settings\.|settings\.[a-z_]+_text)")

DOM_SINK = re.compile(r"(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\()[^;\n]*(\$\{|\+\s*[a-zA-Z_])")
EXTERNAL_SRC = re.compile(r"<(script|link)\b(?![^>]*rel=\"(preconnect|dns-prefetch)\")[^>]*(src|href)=\"(https?:)?//(?!cdn\.shopify\.com|fonts\.shopifycdn\.com|[a-z0-9-]+\.myshopify\.com)([^\"]+)\"[^>]*>", re.I)
CSS_EXTERNAL = re.compile(r"url\(['\"]?(https?:)?//(?!cdn\.shopify\.com)([^)'\"]+)")
INSECURE_URL = re.compile(r"(?<!xmlns=\")(?<!:inkscape=\")(?<!:sodipodi=\")(?<!:rdf=\")(?<!:cc=\")(?<!:dc=\")(?<!:svg=\")(?<!:xlink=\")http://(?!www\.inkscape\.org|sodipodi\.sourceforge\.net|creativecommons\.org|www\.w3\.org|schema\.org|ns\.adobe\.com|purl\.org|localhost|127\.0\.0\.1)[^\s\"'<>)]+")
DEBUG_CODE = re.compile(r"\b(console\.(log|debug)\s*\(|debugger\s*;)")
TODO = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
BLANK_TARGET = re.compile(r"<a\b(?![^>]*\brel=)[^>]*target=\"_blank\"[^>]*>", re.I)
ALL_PRODUCTS = re.compile(r"all_products\[")
STOCK_RENDER = re.compile(r"render\s+'stock-image'")

# Default copy shipped with themes / Shopify that should never reach launch
DEFAULT_COPY = [
    "Announce something here",
    "Share some content to your customers",
    "Share information about your brand",
    "Lorem ipsum",
    "Your headline",
    "Example product",
    "Talk about your brand",
]


def scan_file(path, rel):
    text = path.read_text(encoding="utf-8", errors="replace")
    is_vendor = rel.parts[0] == "assets" and rel.name in {"theme.js", "vendor.min.js", "photoswipe.min.js"}
    is_locale = rel.parts[0] == "locales"

    # Secrets (everywhere, including locales)
    for pattern, label in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if is_locale and label == "Hard-coded credential":
                continue
            add("blocker", "security/secret", rel, line_of(text, m.start()), f"{label} committed to the repo", m.group(0)[:40] + "…")

    if is_locale:
        return

    if path.suffix == ".liquid":
        # Reflected visitor input without escaping
        for m in VISITOR_INPUT.finditer(text):
            if ESCAPED.search(m.group(0)):
                continue
            if PLATFORM_ESCAPED.search(m.group(0)):
                add("info", "security/xss", rel, line_of(text, m.start()),
                    "Visitor input output without | escape; Shopify escapes this value itself, so no action unless the theme decodes it", m.group(0))
            else:
                add("high", "security/xss", rel, line_of(text, m.start()), "Visitor-controlled value output without | escape", m.group(0))

        # Liquid values dropped into inline JavaScript without | json
        for block_re in (SCRIPT_BLOCK, JS_LIQUID_BLOCK):
            for block in block_re.finditer(text):
                for out in LIQUID_OUTPUT.finditer(block.group(1)):
                    expr = out.group(1)
                    if TEXTY_LIQUID.search(expr) and "json" not in expr and "asset_url" not in expr:
                        idx = block.start(1) + out.start()
                        add("medium", "security/script-injection", rel, line_of(text, idx),
                            "Text value inserted into <script> without | json (quotes or </script> in the text would break out)", out.group(0))

        for m in EXTERNAL_SRC.finditer(text):
            tag = m.group(0)
            sev = "medium" if m.group(1).lower() == "script" and "integrity=" not in tag else "low"
            add(sev, "security/third-party", rel, line_of(text, m.start()),
                "Third-party " + m.group(1).lower() + (" without integrity hash" if "integrity=" not in tag else "") +
                " (also a privacy/GDPR consideration: visitor IPs go to that host)", tag)

        for m in BLANK_TARGET.finditer(text):
            add("low", "security/tabnabbing", rel, line_of(text, m.start()), 'target="_blank" link without rel="noopener"', m.group(0))

        for m in ALL_PRODUCTS.finditer(text):
            add("medium", "shopify/limits", rel, line_of(text, m.start()),
                "all_products[] lookups are capped at 20 unique handles per page; extra lookups silently return nothing",
                text[m.start():m.start() + 80].splitlines()[0])

        for m in STOCK_RENDER.finditer(text):
            add("blocker", "content/placeholder", rel, line_of(text, m.start()),
                "Temporary stock photo fallback still wired in; real photography should replace it before launch",
                text[m.start():m.start() + 80].splitlines()[0])

    # Risky DOM writes with dynamic data (custom code; vendor bundle reported once as info)
    if path.suffix in {".js", ".liquid"}:
        for m in DOM_SINK.finditer(text):
            sev = "info" if is_vendor else "medium"
            add(sev, "security/dom-xss", rel, line_of(text, m.start()),
                "HTML built from dynamic values; confirm the values can never contain visitor or merchant-entered HTML", m.group(0))

    for m in CSS_EXTERNAL.finditer(text):
        add("low", "privacy/third-party", rel, line_of(text, m.start()),
            "Asset loaded from a third-party host (visitor IP shared with it; consider self-hosting in assets/)", m.group(0))

    for m in INSECURE_URL.finditer(text):
        add("medium", "security/mixed-content", rel, line_of(text, m.start()), "Insecure http:// URL (blocked or warned on an https store)", m.group(0))

    if not is_vendor:
        for m in DEBUG_CODE.finditer(text):
            add("low", "cleanup/debug", rel, line_of(text, m.start()), "Debug statement left in code", text[m.start():m.start() + 60].splitlines()[0])
        for m in TODO.finditer(text):
            add("info", "cleanup/todo", rel, line_of(text, m.start()), "TODO/FIXME marker", text[m.start():m.start() + 80].splitlines()[0])

    if path.suffix == ".json" or path.suffix == ".liquid":
        for phrase in DEFAULT_COPY:
            for m in re.finditer(re.escape(phrase), text, re.I):
                # Schema defaults inside {% schema %} only matter if a section actually uses them
                in_schema = path.suffix == ".liquid" and "{% schema %}" in text and m.start() > text.find("{% schema %}")
                if in_schema:
                    continue
                add("high", "content/placeholder", rel, line_of(text, m.start()), f'Default/demo copy "{phrase}" still in the theme', text[max(0, m.start() - 30):m.end() + 30])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = Path(args[0] if args else ".").resolve()
    as_json = "--json" in sys.argv

    if not (root / "layout" / "theme.liquid").exists():
        sys.exit(f"{root} does not look like a Shopify theme (no layout/theme.liquid)")

    for path in iter_files(root):
        scan_file(path, path.relative_to(root))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["category"], f["file"], f["line"]))

    if as_json:
        print(json.dumps(findings, indent=2))
        return

    if not findings:
        print("No findings.")
        return

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("Summary: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if s in counts))
    current = None
    for f in findings:
        if f["severity"] != current:
            current = f["severity"]
            print(f"\n## {current.upper()}")
        print(f"- [{f['category']}] {f['file']}:{f['line']}: {f['message']}")
        if f["snippet"]:
            print(f"    {f['snippet']}")


if __name__ == "__main__":
    main()
