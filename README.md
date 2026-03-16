# CognitiveCTI Blog Theme

A clean, lightweight Jekyll theme for cyber threat intelligence publishing. Designed as a drop-in replacement for the default Jekyll project — no plugins beyond the standard trio, no JavaScript frameworks, no build tools.

Inspired by [rubyonrails.org](https://rubyonrails.org/). Built to present intelligence from the [CognitiveCTI pipeline](https://github.com/jwhitt3r/cognitiveCTI).

## Features

- **Light & dark mode** — respects OS preference, persists user choice, no flash on load
- **Category filtering** — daily briefs, weekly reports, monthly landscapes, bespoke analyses
- **RSS/Atom feed** — first-class output for SIEM/SOAR/reader ingestion via `jekyll-feed`
- **Severity badges** — critical / high / medium / low / info visual indicators
- **Security hardened** — CSP headers, X-Frame-Options, HSTS, Permissions-Policy
- **Static by nature** — no databases, no server-side code, no client-side frameworks
- **Accessible** — semantic HTML, ARIA labels, keyboard navigation, focus indicators
- **SEO** — Open Graph, JSON-LD via `jekyll-seo-tag`, sitemap via `jekyll-sitemap`

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-org/cognitivecti-blog.git
cd cognitivecti-blog

# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Build for production
JEKYLL_ENV=production bundle exec jekyll build
```

Open `http://localhost:4000` in your browser.

## Configuration

Edit `_config.yml`:

```yaml
title: CognitiveCTI
tagline: "Automated Threat Intelligence — Daily · Weekly · Monthly"
description: >-
  Your site description here.
url: "https://cti.yourdomain.com"
```

## Writing Posts

### Daily Brief

```yaml
---
title: "Daily Brief — Short Description"
date: 2026-03-15
category: daily
severity: critical
description: "One-line executive summary."
sources:
  - Microsoft
  - BleepingComputer
reports_processed: 45
correlation_batches: 2
---

Your markdown content here.
```

### Weekly Report

```yaml
---
title: "Weekly Report — W11 2026: Headline"
date: 2026-03-14
category: weekly
severity: high
description: "Week summary."
reports_processed: 312
correlation_batches: 14
---
```

### Monthly Landscape

```yaml
---
title: "Monthly Landscape — February 2026: Headline"
date: 2026-03-01
category: monthly
severity: high
---
```

### Bespoke Analysis

Place analysis posts in the `_analyses/` collection directory:

```yaml
---
title: "Analysis: Campaign or Trend Name"
date: 2026-03-10
category: analysis
severity: medium
description: "What this analysis covers."
---
```

### Front Matter Reference

| Field | Required | Values |
|-------|----------|--------|
| `title` | Yes | Post title |
| `date` | Yes | `YYYY-MM-DD` |
| `category` | Yes | `daily`, `weekly`, `monthly`, `analysis` |
| `severity` | No | `critical`, `high`, `medium`, `low`, `info` |
| `description` | No | One-line summary (used in meta tags and post header) |
| `sources` | No | Array of source names |
| `reports_processed` | No | Integer — shown in post footer |
| `correlation_batches` | No | Integer — shown in post footer |

## RSS Feed

The Atom feed is served at `/feed.xml` and includes all posts (daily, weekly, monthly) and analyses. It is configured to include full post content (not excerpts only) with a limit of 50 items.

**Integration examples:**

- **Slack:** Use `/feed` with an RSS app to post new briefs to a channel
- **SIEM:** Most SIEM platforms can ingest RSS as a threat intelligence source
- **Readers:** Any Atom/RSS reader (Feedly, Miniflux, NewsBlur, etc.)

## Deployment

### GitHub Pages

Push to `main`. The included `.github/workflows/pages.yml` handles the build and deploy.

### Netlify

Push to your connected repo. The `netlify.toml` and `_headers` file handle build config and security headers.

### Any Static Host

```bash
JEKYLL_ENV=production bundle exec jekyll build
# Upload the _site/ directory to your host
```

For hosts other than Netlify, configure equivalent security headers in your web server config. See `_headers` for the recommended policy.

## Security

The theme is hardened for static hosting:

- **Content Security Policy** — restricts script, style, font, and image sources; blocks frames, objects, and form actions
- **Strict-Transport-Security** — enforces HTTPS with preload
- **X-Frame-Options: DENY** — prevents clickjacking
- **X-Content-Type-Options: nosniff** — prevents MIME sniffing
- **Referrer-Policy: strict-origin-when-cross-origin** — limits referrer leakage
- **Permissions-Policy** — disables camera, microphone, geolocation, payment, USB
- **Cross-Origin policies** — same-origin opener, embedder, and resource policies
- **No inline scripts** — all JavaScript is in external files loaded with `defer`
- **No third-party JS** — only Google Fonts CSS is loaded externally
- **No cookies, no analytics, no tracking**

## Directory Structure

```
.
├── _config.yml              # Site configuration
├── _layouts/
│   ├── default.html         # Root template
│   ├── home.html            # Index with filtering
│   ├── post.html            # Single intelligence post
│   └── page.html            # Static pages
├── _includes/
│   ├── head.html            # <head> with CSP meta, fonts, RSS
│   ├── header.html          # Navigation bar
│   └── footer.html          # Footer with RSS link
├── _sass/
│   ├── _variables.scss      # Design tokens
│   ├── _base.scss           # Reset, typography, themes
│   ├── _layout.scss         # Components, grid, navigation
│   └── _syntax.scss         # Rouge code highlighting
├── assets/
│   ├── css/main.scss        # Sass entry point
│   └── js/theme.js          # Theme toggle (47 lines)
├── _posts/                  # Daily, weekly, monthly posts
├── _analyses/               # Bespoke analysis collection
├── pages/
│   └── about.md             # About page
├── _headers                 # Netlify security headers
├── netlify.toml             # Netlify build config
├── .github/workflows/       # GitHub Pages CI
├── 404.html                 # Custom 404
├── robots.txt               # Search engine directives
├── index.html               # Home page
└── Gemfile                  # Ruby dependencies
```

## Dependencies

Only three Jekyll plugins — all are GitHub Pages whitelisted:

- `jekyll-feed` — Atom feed generation
- `jekyll-seo-tag` — SEO meta tags
- `jekyll-sitemap` — XML sitemap

No JavaScript frameworks. No build tools beyond Bundler. No Node.js.

## Credits

- Theme inspired by [rubyonrails.org](https://rubyonrails.org/)
- Pipeline: [CognitiveCTI](https://github.com/jwhitt3r/cognitiveCTI)
- Architecture: [Building a Scalable, Self-Hosted Threat Intelligence Pipeline with AI](https://blog.overresearched.net/2026/03/cognitive-cti-building-scalable-self.html)

## License

MIT
