---
name: launch-check
description: Pre-launch audit for this Shopify theme and its live storefront. Scans the theme code for security problems (committed secrets, unescaped output, risky DOM writes, insecure URLs, third-party scripts), leftover placeholder or demo content, and Shopify gotchas; then audits the live store with Playwright (accessibility, console errors, failed requests, broken links, SEO, security headers, page weight, LCP, missing policies); then walks the Shopify admin launch checklist. Use this whenever someone asks to check the site before launch, run a security or vulnerability check, find what is missing, do a go-live or launch readiness review, re-check after a big theme change, or asks "are we ready to launch?", even if they don't say "audit".
---

# Launch check

A pre-launch audit for the Elliott and Me Shopify theme. It has three parts that catch different kinds of problems:

1. **Theme code scan**: things that are wrong in the repo itself.
2. **Live storefront audit**: things that only show up when the real store renders (content entered in Shopify admin, apps, policies, real links).
3. **Admin checklist**: launch settings that live only in Shopify admin and can't be seen from code or the storefront.

The person asking is usually the store owner, not a developer. The deliverable is a short, ranked list of what to fix before launch, in plain language, with where each fix happens (repo file, or which admin screen).

## 1. Theme code scan

Run from the repo root:

```bash
python3 .claude/skills/launch-check/scripts/theme_scan.py .
```

(`--json` gives machine-readable output.) The scan is heuristic on purpose: it points at a file and line, and you confirm before reporting. When triaging:

- **Confirm before calling something a vulnerability.** Open the line. A `security/dom-xss` hit is only a problem if the interpolated value can contain visitor or merchant-entered HTML; a heading level number is not.
- `security/xss` at **info** level covers `search.terms`, `form.errors` and `request.path`. Shopify escapes these itself (verified on this store: searching `"><i>x</i>` renders as `&quot;&amp;gt;x`). Mention them only if the theme decodes or re-injects them.
- `content/placeholder` blockers (stock photos, theme demo copy) matter for launch even though they are not security issues; customers see them.
- `shopify/limits` (`all_products[]`) is capped at 20 unique handles per page. The color-sibling swatches use it; fine with today's 10 colors, but say so if the color list grows.
- Third-party hosts (fonts from jsDelivr, etc.) are a privacy note: the visitor's IP goes to that host. Self-hosting the file in `assets/` removes it.

If the Shopify CLI is installed (`shopify version`), also run `shopify theme check --path .` and fold its errors into the report. Skip quietly if it isn't. Known noise on this theme: `MissingAsset` for `checkmark.svg` / `cursor-zoom-in.svg` (they exist as `.svg.liquid`, which Shopify compiles), and the `ValidDocParamTypes`, `ValidSchemaTranslations`, `ValidBlockTarget` and `MissingRenderSnippetArguments` hits that ship with the Prestige base theme. Report new errors in files this repo changed; summarize the rest as one line.

## 2. Live storefront audit

Use the Playwright MCP tools.

1. Navigate to the store (`https://elliottandme.com/`). If it redirects to `/password`, the store is locked: ask the person for the storefront password (never write it to a file, commit it, or repeat it back), then unlock with `browser_evaluate`:
   `() => { const i = document.querySelector('input[type="password"][name="password"]'); i.value = '<password>'; i.form.submit(); }`
   The password field is usually hidden behind an "Enter using password" button, so fill it through the DOM rather than clicking.
2. Run the audit script with `browser_run_code_unsafe` and the **absolute** path:
   `filename: <repo>/.claude/skills/launch-check/scripts/live_audit.js`
   It visits home, a collection, a product, a content page, blog (if any), search, cart, a 404 and the four policy pages, then checks every internal link it found. Expect a few minutes.
3. Read the JSON and interpret it. Things that look alarming but usually aren't:
   - `favicon.ico` 404 is normal on Shopify; check `favicon: true` on pages instead (the theme links its own icon).
   - The 404 page logs one "Failed to load resource: 404" console error: that's the page itself, expected.
   - `og:image` starting with `http:` is the theme's standard pattern; `og:image:secure_url` carries the https copy.
   - Search pages are heavy because they load every result image; judge speed on home, collection and product.
   - Security headers (HSTS, CSP, X-Frame-Options, nosniff) are set by Shopify, not the theme. Report only if one is missing.
   - Multiple `h1` on the home page can come from the hero slideshow's loop clones (they're `aria-hidden` and inert). Report as minor SEO.
4. Things that are real launch problems: any **policy page returning 404**, `placeholderAlt` counts (product photo alt text that says placeholder/stock means real photos and descriptions are still missing), missing meta descriptions on home/collections, missing `og:image` on the home page (no social sharing image), `robots` `noindex` on public pages, broken links, console errors from theme code, failed requests from apps, accessibility violations, and `insecureRequests`.

The script leaves Playwright logs in `.playwright-mcp/` (git-ignored). Delete the folder afterwards if it's inside the repo.

## 3. Admin checklist

Read `references/admin-checklist.md` and go through it with the person. Mark items the audit already answered (e.g. policies 404 means "Policies" is not done). For the rest, ask rather than assume; these settings are invisible from code.

## Report

Lead with whether the store is ready, then the ranked list. Keep it to what someone needs to act on:

```
**Launch readiness:** <ready / not yet: N blockers>

### Blockers (fix before removing the password)
- <problem, in plain words>: <where to fix: file:line or Admin → screen>. <one-line why>

### Should fix soon
- ...

### Nice to have
- ...

### Checked and fine
<one line listing what passed: security headers, broken links (N checked), accessibility (N pages), console errors, mixed content…>

### Couldn't check
<anything skipped: CLI not installed, store locked without a password, admin-only items not confirmed>
```

Offer to fix the repo-side items. Commit only when asked.
