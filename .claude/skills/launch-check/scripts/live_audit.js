// Live storefront audit, run through the Playwright MCP tool:
//   browser_run_code_unsafe({ filename: ".claude/skills/launch-check/scripts/live_audit.js" })
//
// Before running: navigate the browser to the store (and get past the password page if it is locked).
// The audit uses the origin of the page that is currently open, visits the key templates, and returns JSON:
// per-page accessibility (axe), console errors, failed requests, mixed content, SEO basics, image weight,
// LCP, page weight and document security headers; then a broken-link check over every internal link found.
async (page) => {
  const origin = new URL(page.url()).origin;
  if (!origin.startsWith('http')) {
    return { error: 'Open the storefront (and unlock it) before running the audit.' };
  }

  const AXE = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js';
  const report = { origin, pages: [], siteFiles: {}, links: { checked: 0, broken: [] }, notes: [] };

  // ---- Discover representative pages from the home page ----------------------------------------------
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  if (page.url().includes('/password')) {
    return { error: 'Storefront is still password-locked in this browser. Unlock it first.' };
  }
  const discovered = await page.evaluate(() => {
    const hrefs = Array.from(document.querySelectorAll('a[href]')).map((a) => a.getAttribute('href'));
    const pick = (re) => hrefs.find((h) => h && re.test(h));
    return {
      collection: pick(/^\/collections\/(?!all\b)[^/?#]+\/?$/) || '/collections/all',
      product: pick(/\/products\/[^/?#]+/),
      page: pick(/^\/pages\/[^/?#]+/),
      blog: pick(/^\/blogs\/[^/?#]+/),
    };
  });
  if (!discovered.product) {
    await page.goto(origin + discovered.collection, { waitUntil: 'domcontentloaded' });
    discovered.product = await page.evaluate(() => document.querySelector('a[href*="/products/"]')?.getAttribute('href'));
  }

  const targets = [
    ['home', '/'],
    ['collection', discovered.collection],
    ['product', discovered.product],
    ['content page', discovered.page],
    ['blog', discovered.blog],
    ['search', '/search?q=baby'],
    ['cart', '/cart'],
    ['404', '/pages/launch-check-missing-page'],
    ['privacy policy', '/policies/privacy-policy'],
    ['refund policy', '/policies/refund-policy'],
    ['terms of service', '/policies/terms-of-service'],
    ['shipping policy', '/policies/shipping-policy'],
  ].filter(([, path]) => path);

  const internalLinks = new Set();

  for (const [name, path] of targets) {
    const url = new URL(path, origin).href;
    const consoleErrors = [];
    const failed = [];
    const insecure = [];
    const onConsole = (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 200)); };
    const onPageError = (err) => consoleErrors.push('Uncaught: ' + String(err.message).slice(0, 200));
    const onResponse = (res) => {
      const u = res.url();
      if (res.status() >= 400 && !u.includes('launch-check-missing-page')) failed.push(`${res.status()} ${u.slice(0, 160)}`);
    };
    const onRequestFailed = (req) => {
      const reason = req.failure()?.errorText || '';
      if (!/ERR_ABORTED/.test(reason)) failed.push(`failed (${reason}) ${req.url().slice(0, 160)}`);
    };
    const onRequest = (req) => { if (req.url().startsWith('http://')) insecure.push(req.url().slice(0, 160)); };

    page.on('console', onConsole);
    page.on('pageerror', onPageError);
    page.on('response', onResponse);
    page.on('requestfailed', onRequestFailed);
    page.on('request', onRequest);

    const entry = { name, url };
    try {
      const response = await page.goto(url, { waitUntil: 'load', timeout: 45000 });
      await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
      entry.status = response?.status();

      const headers = response?.headers() || {};
      entry.securityHeaders = {
        'strict-transport-security': headers['strict-transport-security'] || null,
        'content-security-policy': headers['content-security-policy'] ? 'present' : null,
        'x-frame-options': headers['x-frame-options'] || null,
        'x-content-type-options': headers['x-content-type-options'] || null,
      };

      // Let lazy content (marquees, recommendations) load
      await page.evaluate(async () => {
        for (let y = 0; y < document.body.scrollHeight; y += 700) { window.scrollTo(0, y); await new Promise((r) => setTimeout(r, 120)); }
        window.scrollTo(0, 0);
      });

      Object.assign(entry, await page.evaluate(() => {
        const meta = (sel) => document.querySelector(sel)?.getAttribute('content') || null;
        const images = Array.from(document.images).filter((img) => img.complete && img.naturalWidth > 0);
        const oversized = images
          .filter((img) => img.clientWidth > 0 && img.naturalWidth > img.clientWidth * window.devicePixelRatio * 2.5 && img.naturalWidth > 1200)
          .slice(0, 5)
          .map((img) => `${img.currentSrc.split('?')[0].split('/').pop()} (${img.naturalWidth}px shown at ${img.clientWidth}px)`);
        const resources = performance.getEntriesByType('resource');
        const nav = performance.getEntriesByType('navigation')[0];
        const bytes = resources.reduce((sum, r) => sum + (r.transferSize || 0), nav?.transferSize || 0);
        return {
          seo: {
            title: document.title,
            titleLength: document.title.length,
            description: meta('meta[name="description"]'),
            canonical: document.querySelector('link[rel="canonical"]')?.href || null,
            robots: meta('meta[name="robots"]'),
            ogImage: meta('meta[property="og:image"]'),
            h1Count: document.querySelectorAll('h1').length,
            lang: document.documentElement.lang || null,
            viewport: meta('meta[name="viewport"]'),
            structuredData: document.querySelectorAll('script[type="application/ld+json"]').length,
          },
          images: {
            missingAlt: Array.from(document.images).filter((img) => !img.hasAttribute('alt')).length,
            placeholderAlt: Array.from(document.images).filter((img) => /placeholder|stock|lorem|image\d*$/i.test(img.alt)).length,
            oversized,
          },
          weight: { requests: resources.length + 1, kilobytes: Math.round(bytes / 1024) },
          domNodes: document.getElementsByTagName('*').length,
          favicon: !!document.querySelector('link[rel~="icon"]'),
          internalLinks: Array.from(document.querySelectorAll('a[href]'))
            .map((a) => a.href)
            .filter((h) => h.startsWith(location.origin) && !h.includes('#') && !/\/(cart|account|checkout)\b/.test(h)),
        };
      }));
      entry.internalLinks.forEach((h) => internalLinks.add(h.split('?')[0]));
      delete entry.internalLinks;

      entry.lcpMs = await page.evaluate(() => new Promise((resolve) => {
        let last = null;
        new PerformanceObserver((list) => { const e = list.getEntries(); last = e[e.length - 1]; }).observe({ type: 'largest-contentful-paint', buffered: true });
        setTimeout(() => resolve(last ? Math.round(last.startTime) : null), 300);
      }));

      await page.addScriptTag({ url: AXE });
      entry.accessibility = await page.evaluate(async () => {
        const result = await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } });
        return result.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, count: v.nodes.length, example: v.nodes[0]?.target.join(' ') }));
      });
    } catch (error) {
      entry.error = String(error.message).slice(0, 200);
    }

    entry.consoleErrors = [...new Set(consoleErrors)].slice(0, 10);
    entry.failedRequests = [...new Set(failed)].slice(0, 10);
    entry.insecureRequests = [...new Set(insecure)].slice(0, 10);
    report.pages.push(entry);

    page.off('console', onConsole);
    page.off('pageerror', onPageError);
    page.off('response', onResponse);
    page.off('requestfailed', onRequestFailed);
    page.off('request', onRequest);
  }

  // ---- Site-level files ------------------------------------------------------------------------------
  for (const file of ['/robots.txt', '/sitemap.xml', '/favicon.ico']) {
    const res = await page.request.get(origin + file).catch(() => null);
    const body = res ? await res.text().catch(() => '') : '';
    report.siteFiles[file] = {
      status: res?.status() ?? 'error',
      ...(file === '/robots.txt' ? { blocksEverything: /Disallow:\s*\/\s*$/m.test(body) && !/Disallow:\s*\/\S/m.test(body) } : {}),
    };
  }

  // ---- Broken internal links ---------------------------------------------------------------------------
  const links = [...internalLinks].slice(0, 200);
  for (const link of links) {
    const res = await page.request.get(link, { maxRedirects: 5, timeout: 20000 }).catch((e) => ({ status: () => 'error: ' + e.message.slice(0, 60) }));
    const status = res.status();
    report.links.checked++;
    if (typeof status !== 'number' || status >= 400) report.links.broken.push(`${status} ${link}`);
  }
  if (internalLinks.size > links.length) report.notes.push(`Only the first ${links.length} of ${internalLinks.size} internal links were checked.`);

  return report;
}
