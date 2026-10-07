# Shopify admin launch checklist

Settings that live only in Shopify admin. Go through them with the store owner; mark anything the live audit already answered.

## Legal and policies
- [ ] **Settings → Policies**: Refund, Privacy, Terms of service, Shipping, and Contact information all filled in (the live audit flags any that return 404). Shopify can generate templates; have them reviewed.
- [ ] **Settings → Customer privacy → Cookie banner**: automated settings on; banner appears once a market that requires it is added.
- [ ] **Settings → Customer privacy → Data sharing opt-out**: on, for US state privacy laws ("Do Not Sell or Share My Personal Information").
- [ ] Accessibility statement page linked from the footer (goal WCAG 2.1 AA, contact email for problems).
- [ ] Footer links to all policies and the contact page.

## Selling
- [ ] **Settings → Payments**: payment provider activated (Shopify Payments verified, payouts bank account added); test mode off.
- [ ] Place a real test order end to end (then refund it): checkout, confirmation email, fulfillment notification.
- [ ] **Settings → Shipping and delivery**: rates for every market you sell to; package weights on products.
- [ ] **Settings → Taxes and duties**: registrations for states where you collect tax.
- [ ] **Settings → Markets**: correct countries and currencies.
- [ ] **Settings → Checkout**: customer contact method, marketing consent wording, order status page.

## Products and content
- [ ] Real product photography uploaded, with descriptive alt text (Products → product → media → "Add alt text").
- [ ] Temporary stock photos removed from the theme (`snippets/stock-image.liquid` and its fallbacks).
- [ ] Prices, inventory and "continue selling when out of stock" correct.
- [ ] Product, collection and page SEO titles and descriptions (each edit page → "Search engine listing").
- [ ] **Online Store → Preferences**: home page title and meta description; social sharing image.
- [ ] Theme editor: no section still showing demo text or placeholders.

## Store identity and email
- [ ] **Settings → Domains**: elliottandme.com primary, SSL active, www redirect working.
- [ ] **Settings → Notifications**: sender email on your own domain (authenticated), branded templates.
- [ ] **Settings → General**: store contact email, address, order ID format.
- [ ] Favicon set in the theme editor (Theme settings → Favicon).

## Security and accounts
- [ ] **Settings → Users**: every staff account has two-step authentication; remove anyone who doesn't need access; least-privilege permissions.
- [ ] Apps: uninstall anything unused (each app is code running on your store and may hold customer data).
- [ ] Change the storefront password that was shared during development, then remove the password page to launch (**Online Store → Preferences → Password protection**).

## Analytics and marketing
- [ ] Google and Meta connected through their Shopify sales channels (so they respect cookie consent), not pasted scripts.
- [ ] Search engines: submit the sitemap (`/sitemap.xml`) in Google Search Console after the password comes off.
