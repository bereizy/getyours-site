# GetYours - Website Sales Platform

A complete e-commerce landing page for selling ready-to-customize small business websites, with automated customer onboarding.

**Live Site:** https://getyours.indirecttek.com

---

## Tech Stack

- **Framework:** Astro + TypeScript
- **Styling:** Tailwind CSS
- **Hosting:** Cloudflare Pages
- **Payments:** Stripe
- **Database:** Google Sheets
- **File Storage:** Cloudflare R2
- **Email:** Resend

---

## Features

### 💳 Stripe Payments
| Tier | Price |
|------|-------|
| Starter (Landscaper) | $699 |
| Professional | $1,499 |
| Medical/Legal | $3,999 |
| Care Plan (monthly) | $49.99 |

### 📧 Email Notifications (via Resend)
| Event | Recipient |
|-------|-----------|
| New payment received | Admin |
| Intake form submitted | Admin |
| Confirmation after intake | Customer (includes support contact) |
| Payment receipt | Customer (via Stripe) |

### 📊 Google Sheets Integration
| Sheet Tab | Data Captured |
|-----------|---------------|
| **Intakes** | Business info, contact, branding colors, domain, social links, services, notes |
| **Payments** | Timestamp, Stripe Session ID, Customer Name, Email, Tier, Amount, Currency, Status |

### 📁 File Storage (Cloudflare R2)
- Customer logo uploads → `submissions/{id}/logo-{filename}`
- Customer photos → `submissions/{id}/photos/{filename}`

---

## Customer Flow

```
1. Customer visits site
         ↓
2. Clicks "Buy Now" on a tier
         ↓
3. Stripe Checkout → Pays
         ↓
4. Stripe webhook → Logs payment to Google Sheets + Emails admin
         ↓
5. Redirect to /thank-you page
         ↓
6. Customer clicks "Start Your Project"
         ↓
7. Fills out intake form at /start
         ↓
8. Submits → Data to Google Sheets + Files to R2
         ↓
9. Admin gets email notification
         ↓
10. Customer gets confirmation email with support contact
```

---

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| Landing | `/` | Sales page with pricing, demos, FAQ |
| Thank You | `/thank-you` | Post-payment confirmation |
| Intake Form | `/start` | Customer onboarding form |

---

## API Endpoints (Cloudflare Functions)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/intake` | Handles form submission → Sheets + R2 + Emails |
| `POST /api/stripe-webhook` | Handles Stripe payment events → Sheets + Email |

---

## Environment Secrets (Cloudflare)

Required secrets in Cloudflare Pages settings:

- `GOOGLE_SERVICE_ACCOUNT_EMAIL` - Google service account email
- `GOOGLE_PRIVATE_KEY` - Google service account private key
- `GOOGLE_SHEET_ID` - Google Sheets document ID
- `NOTIFICATION_EMAIL` - Admin email for notifications
- `RESEND_API_KEY` - Resend API key for emails
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret

---

## Local Development

1. Clone the repo
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create `.dev.vars` file with secrets (see `.dev.vars.example`)
4. Run dev server:
   ```bash
   npm run dev
   ```
5. Or test with Cloudflare Functions:
   ```bash
   npm run build && npx wrangler pages dev dist --port 8789
   ```

---

## Deployment

Deploy to Cloudflare Pages:

```bash
npm run build
npx wrangler pages deploy dist --project-name getyours-site
```

---

## Monthly Costs

| Service | Cost |
|---------|------|
| Cloudflare Pages | Free |
| Cloudflare R2 | ~$0.015/GB |
| Resend | Free (up to 3k emails/month) |
| Google Sheets | Free |
| **Total** | **~$0/month** until you scale |

---

## Google Sheet Setup

Create a Google Sheet with two tabs:

### Tab 1: "Intakes" (default sheet)
Headers: `Timestamp | Business Name | Industry | Service Area | Services | Contact Name | Email | Phone | Address | Primary Color | Secondary Color | Accent Color | Text Color | Domain | Facebook | Instagram | Google | Yelp | Logo URL | Photos URLs | Notes`

### Tab 2: "Payments"
Headers: `Timestamp | Stripe Session ID | Customer Name | Customer Email | Tier | Amount | Currency | Status`

---

## Stripe Setup

1. Create payment links for each tier
2. Set success URL to `https://getyours.indirecttek.com/thank-you`
3. Create webhook endpoint: `https://getyours.indirecttek.com/api/stripe-webhook`
4. Subscribe to `checkout.session.completed` event
5. Enable customer receipts in Stripe Settings → Customer emails
