# GetYours - Automated Website Factory

A complete platform for selling and auto-generating small business websites. Customer fills a form → live website in ~60 seconds.

**Live Site:** https://getyours.indirecttek.com

---

## Architecture Overview

```
Customer Journey:
1. Customer visits getyours.indirecttek.com
2. Pays via Stripe → Redirected to /thank-you
3. Fills intake form at /start
4. Form submission triggers automation pipeline

Automation Pipeline (Cloudflare Pages Function with waitUntil):
  Step 1: Create GitHub repo from template
  Step 2: Upload customer images to repo
  Step 3: Claude AI generates siteConfig.ts
  Step 4: Commit siteConfig.ts to repo
  Step 5: Commit tailwind.config.cjs with brand colors
  Step 6: Create Cloudflare Pages project
  Step 7: Trigger site-deployer GitHub Action
          → bereizy/site-deployer workflow:
            - Clones customer repo
            - npm ci && npm run build
            - wrangler pages deploy
  Step 8: Update Google Sheet with status
  Step 9: Send success email to admin

Result: LIVE WEBSITE at {project-name}.pages.dev (~60 seconds)
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | Astro 4.16 + TypeScript + Tailwind CSS |
| Hosting | Cloudflare Pages + Functions |
| Site Templates | @indirecttek/essentials-engine (npm) |
| AI Content | Claude API (claude-sonnet-4-20250514) |
| Repo Management | GitHub API |
| Deployment | GitHub Actions + Wrangler |
| Payments | Stripe Checkout |
| Database | Google Sheets |
| File Storage | Cloudflare R2 |
| Email | Resend |

---

## Repository Structure

```
getyours-site/
├── src/
│   ├── pages/
│   │   ├── index.astro        # Landing/sales page
│   │   ├── start.astro        # Intake form
│   │   └── thank-you.astro    # Post-payment page
│   └── styles/
│       └── global.css
├── functions/
│   └── api/
│       ├── intake.ts          # Main automation handler
│       └── stripe-webhook.ts  # Payment processing
├── public/
├── astro.config.mjs
├── tailwind.config.cjs
└── package.json
```

---

## Environment Secrets

### Cloudflare Pages (getyours-site)

| Secret | Purpose |
|--------|---------|
| GOOGLE_SERVICE_ACCOUNT_EMAIL | Google Sheets API auth |
| GOOGLE_PRIVATE_KEY | Google Sheets API auth |
| GOOGLE_SHEET_ID | Target spreadsheet |
| NOTIFICATION_EMAIL | Admin notification recipient |
| RESEND_API_KEY | Email sending |
| STRIPE_WEBHOOK_SECRET | Payment verification |
| GITHUB_PAT | GitHub API (fine-grained: repo, workflow, Actions:write) |
| ANTHROPIC_API_KEY | Claude AI for content generation |
| CLOUDFLARE_API_TOKEN | Pages project creation |
| CLOUDFLARE_ACCOUNT_ID | Cloudflare account |

### GitHub Repo (bereizy/site-deployer)

| Secret | Purpose |
|--------|---------|
| GH_PAT | Clone private customer repos |
| CLOUDFLARE_API_TOKEN | Deploy to Pages |
| CLOUDFLARE_ACCOUNT_ID | Cloudflare account |

---

## Template Mapping

```typescript
const TEMPLATE_MAP = {
  // Starter Tier ($699)
  'landscaping': 'essentials-tax-starter',
  'pressure-washing': 'essentials-tax-starter',
  'auto-detailing': 'essentials-tax-starter',
  'home-cleaning': 'essentials-tax-starter',
  'handyman': 'essentials-tax-starter',
  'junk-removal': 'essentials-tax-starter',
  'pool-cleaning': 'essentials-tax-starter',
  'painting': 'essentials-tax-starter',

  // Professional Tier ($1,499)
  'real-estate': 'essentials-real-estate-starter',
  'tax-accounting': 'essentials-tax-starter',
  'consulting': 'essentials-tax-starter',
  'insurance': 'essentials-tax-starter',
  'legal': 'essentials-tax-starter',
  'photography': 'essentials-real-estate-starter',
  'salon': 'essentials-real-estate-starter',
  'fitness': 'essentials-real-estate-starter',

  // Medical Tier ($3,999)
  'dental': 'essentials-tax-starter',
  'medical': 'essentials-tax-starter',
  'chiropractic': 'essentials-tax-starter',
  'therapy': 'essentials-tax-starter',
};
```

Template Repos (must be marked as templates on GitHub):
- bereizy/essentials-tax-starter
- bereizy/essentials-real-estate-starter

---

## Repo Naming Convention

```
{template-prefix}-{business-slug}-{last-name}

Examples:
- tax-pacific-auto-detailing-shine
- real-estate-summit-realty-group-johnson
```

---

## Google Sheet Schema (Columns A-Y)

| Column | Field |
|--------|-------|
| A | Timestamp |
| B | Business Name |
| C | Industry |
| D | Service Area |
| E | Services |
| F | Contact Name |
| G | Email |
| H | Phone |
| I | Address |
| J | Primary Color |
| K | Secondary Color |
| L | Accent Color |
| M | Text Color |
| N | Domain |
| O | Facebook |
| P | Instagram |
| Q | Google |
| R | Yelp |
| S | Logo URL |
| T | Photos URLs |
| U | Notes |
| V | Tier |
| W | Repo URL |
| X | Automation Status |
| Y | Preview URL |

### Automation Status Values:
- pending - Initial state
- repo_created - GitHub repo created
- images_committed - Customer images uploaded
- config_generated - Claude generated siteConfig
- code_committed - Config files committed
- pages_created - Cloudflare Pages project created
- deploy_triggered - GitHub Action started
- complete_no_deploy - Done but no auto-deploy
- error: {message} - Something failed

---

## Deployment Commands

### Deploy getyours-site:
```bash
cd getyours-site
npm run build
npx wrangler pages deploy dist --project-name getyours-site
```

### Update site-deployer workflow:
```bash
cd /path/to/site-deployer
git add -A && git commit -m "update" && git push
```

---

## Troubleshooting

### Workflow not triggering (403 error)
Problem: Resource not accessible by personal access token

Solution: Your GitHub PAT needs:
- For fine-grained PAT: Add Actions: Read and write permission
- For classic PAT: repo + workflow scopes
- The PAT must have access to site-deployer repo

### Repo creation fails
Problem: GitHub create repo failed

Solutions:
- Check that template repo exists and is marked as template
- Verify GITHUB_PAT has repo scope
- Ensure repo name doesn't already exist

### Claude API fails
Problem: Claude API error

Solutions:
- Verify ANTHROPIC_API_KEY is valid
- Check API quota/billing

### Pages project creation fails
Problem: Cloudflare Pages creation failed

Solutions:
- Verify CLOUDFLARE_API_TOKEN has Pages edit permission
- Check CLOUDFLARE_ACCOUNT_ID is correct
- Project names must be <= 58 chars, lowercase, alphanumeric + hyphens

### Build fails in GitHub Action
Problem: Workflow runs but deployment fails

Solutions:
- Check GH_PAT in site-deployer secrets can access customer repos
- Verify customer repo has valid package.json and build script
- Check CLOUDFLARE_API_TOKEN in site-deployer has Pages deploy permission

---

## Pricing Tiers

| Tier | Price | Industries |
|------|-------|------------|
| Starter | $699 | Landscaping, Pressure Washing, Auto Detailing, Cleaning, Handyman, Junk Removal, Pool, Painting |
| Professional | $1,499 | Real Estate, Tax, Consulting, Insurance, Legal, Photography, Salon, Fitness, Tech Repair |
| Medical | $3,999 | Dental, Medical, Chiropractic, Therapy, Optometry, Veterinary, Aesthetics |
| Care Plan | $49.99/mo | Hosting, SSL, updates, minor changes |

---

## Cleanup Commands

```bash
# Delete test repos:
gh repo delete bereizy/{repo-name} --yes

# Delete test Pages projects:
npx wrangler pages project delete {project-name}

# List all repos:
gh repo list bereizy --limit 50 --json name

# List all Pages projects:
npx wrangler pages project list
```

---

## Email Notifications

| Event | Recipient | Content |
|-------|-----------|---------|
| New intake | Admin | Full business details |
| Intake confirmation | Customer | What was received, timeline, Care Plan upsell |
| Automation success | Admin | Repo URL, preview URL, status |
| Payment received | Admin | Stripe session details |

---

## Important URLs

| Resource | URL |
|----------|-----|
| Live Site | https://getyours.indirecttek.com |
| Intake Form | https://getyours.indirecttek.com/start |
| Site Deployer Repo | https://github.com/bereizy/site-deployer |
| GitHub Actions | https://github.com/bereizy/site-deployer/actions |
| Cloudflare Dashboard | https://dash.cloudflare.com |

---

## Local Development

1. Clone the repo
2. Install dependencies: `npm install`
3. Create .dev.vars file with secrets (copy from Cloudflare)
4. Run dev server: `npm run dev`
5. Or test with Cloudflare Functions:
   ```bash
   npm run build && npx wrangler pages dev dist --port 8789
   ```

---

## Working Pipeline Checklist

- [x] Customer fills intake form
- [x] Data saved to Google Sheets
- [x] Email notifications sent
- [x] GitHub repo created from template
- [x] Claude AI generates siteConfig.ts
- [x] Tailwind brand colors applied
- [x] Cloudflare Pages project created
- [x] GitHub Action auto-triggered
- [x] Site built and deployed
- [x] Live in ~60 seconds

---

*Last updated: January 12, 2026*
