// Cloudflare Pages Function - handles /api/intake POST requests
// Saves data to Google Sheets, sends email notification, creates GitHub repo, generates site

interface Env {
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string;
  GOOGLE_PRIVATE_KEY: string;
  GOOGLE_SHEET_ID: string;
  NOTIFICATION_EMAIL: string;
  RESEND_API_KEY?: string;
  R2_BUCKET?: R2Bucket;
  GITHUB_PAT?: string;
  ANTHROPIC_API_KEY?: string;
  CLOUDFLARE_API_TOKEN?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
}

// Template mapping based on industry
// NOTE: Only essentials-real-estate-starter and essentials-tax-starter exist for now
// All industries are mapped to one of these two templates
const TEMPLATE_MAP: Record<string, { template: string; tier: string }> = {
  // Starter Tier ($699) - Service-based trades
  // Using tax template as it's more service-oriented
  'landscaping': { template: 'essentials-tax-starter', tier: 'starter' },
  'pressure-washing': { template: 'essentials-tax-starter', tier: 'starter' },
  'auto-detailing': { template: 'essentials-tax-starter', tier: 'starter' },
  'home-cleaning': { template: 'essentials-tax-starter', tier: 'starter' },
  'handyman': { template: 'essentials-tax-starter', tier: 'starter' },
  'junk-removal': { template: 'essentials-tax-starter', tier: 'starter' },
  'pool-cleaning': { template: 'essentials-tax-starter', tier: 'starter' },
  'painting': { template: 'essentials-tax-starter', tier: 'starter' },
  
  // Professional Tier ($1,499) - Credentialed pros
  'real-estate': { template: 'essentials-real-estate-starter', tier: 'professional' },
  'tax-accounting': { template: 'essentials-tax-starter', tier: 'professional' },
  'consulting': { template: 'essentials-tax-starter', tier: 'professional' },
  'insurance': { template: 'essentials-tax-starter', tier: 'professional' },
  'legal': { template: 'essentials-tax-starter', tier: 'professional' },
  'photography': { template: 'essentials-real-estate-starter', tier: 'professional' },
  'salon': { template: 'essentials-real-estate-starter', tier: 'professional' },
  'fitness': { template: 'essentials-real-estate-starter', tier: 'professional' },
  'tech-repair': { template: 'essentials-tax-starter', tier: 'professional' },
  
  // Medical Tier ($3,999) - Regulated practices
  // Using tax template until dental template is created
  'dental': { template: 'essentials-tax-starter', tier: 'medical' },
  'medical': { template: 'essentials-tax-starter', tier: 'medical' },
  'chiropractic': { template: 'essentials-tax-starter', tier: 'medical' },
  'therapy': { template: 'essentials-tax-starter', tier: 'medical' },
  'optometry': { template: 'essentials-tax-starter', tier: 'medical' },
  'veterinary': { template: 'essentials-tax-starter', tier: 'medical' },
  'medical-aesthetics': { template: 'essentials-tax-starter', tier: 'medical' },
  
  // Fallback
  'other': { template: 'essentials-tax-starter', tier: 'starter' },
};

const GITHUB_OWNER = 'bereizy';

// Type for execution context with waitUntil
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  const ctx = context as unknown as { waitUntil: (p: Promise<unknown>) => void };

  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  try {
    const timestamp = new Date().toISOString();
    const contentType = request.headers.get('Content-Type') || '';
    
    // Parse request body - support both JSON and FormData
    let rawData: Record<string, string | File | null> = {};
    
    if (contentType.includes('application/json')) {
      rawData = await request.json() as Record<string, string>;
    } else {
      const formData = await request.formData();
      // Extract all form fields including files
      for (const [key, value] of formData.entries()) {
        rawData[key] = value;
      }
    }

    // Build data object from parsed input
    const data: Record<string, string> = {
      timestamp,
      businessName: String(rawData.businessName || ''),
      industry: String(rawData.industry || ''),
      serviceArea: String(rawData.serviceArea || ''),
      services: String(rawData.services || ''),
      contactName: String(rawData.contactName || ''),
      email: String(rawData.email || ''),
      phone: String(rawData.phone || ''),
      address: String(rawData.address || ''),
      primaryColor: String(rawData.primaryColor || ''),
      secondaryColor: String(rawData.secondaryColor || ''),
      accentColor: String(rawData.accentColor || ''),
      textColor: String(rawData.textColor || ''),
      domain: String(rawData.domain || ''),
      facebook: String(rawData.facebook || ''),
      instagram: String(rawData.instagram || ''),
      google: String(rawData.google || ''),
      yelp: String(rawData.yelp || ''),
      logoUrl: '',
      photosUrls: '',
      notes: String(rawData.notes || ''),
      tier: '',
      repoUrl: '',
      previewUrl: '',
      automationStatus: 'pending',
    };

    // Generate unique submission ID and repo name
    const lastName = data.contactName.split(' ').pop()?.toLowerCase() || 'client';
    const businessSlug = data.businessName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const templateInfo = TEMPLATE_MAP[data.industry] || TEMPLATE_MAP['other'];
    const repoName = `${templateInfo.template.replace('essentials-', '').replace('-starter', '')}-${businessSlug}-${lastName}`;
    const submissionId = `${Date.now()}-${businessSlug}`;
    
    // Set the tier based on industry mapping
    data.tier = templateInfo.tier;

    // Collect uploaded files info for later
    const uploadedFiles: { key: string; data: ArrayBuffer; contentType: string; filename: string }[] = [];

    // Handle file uploads to R2 if available (only for FormData requests)
    if (env.R2_BUCKET && !contentType.includes('application/json')) {
      const logoFile = rawData.logo;
      if (logoFile && logoFile instanceof File && logoFile.size > 0) {
        const logoKey = `submissions/${submissionId}/logo-${logoFile.name}`;
        const logoData = await logoFile.arrayBuffer();
        await env.R2_BUCKET.put(logoKey, logoData, {
          httpMetadata: { contentType: logoFile.type },
        });
        data.logoUrl = logoKey;
        uploadedFiles.push({ key: logoKey, data: logoData, contentType: logoFile.type, filename: `logo-${logoFile.name}` });
      }

      // For photos, we need to re-parse formData to get multiple files
      const formData = await request.clone().formData();
      const photosFiles = formData.getAll('photos') as File[];
      const photoKeys: string[] = [];
      for (const photo of photosFiles) {
        if (photo && photo.size > 0) {
          const photoKey = `submissions/${submissionId}/photos/${photo.name}`;
          const photoData = await photo.arrayBuffer();
          await env.R2_BUCKET.put(photoKey, photoData, {
            httpMetadata: { contentType: photo.type },
          });
          photoKeys.push(photoKey);
          uploadedFiles.push({ key: photoKey, data: photoData, contentType: photo.type, filename: photo.name });
        }
      }
      data.photosUrls = photoKeys.join('\n');
    } else if (!contentType.includes('application/json')) {
      // No R2 - note file upload status (FormData only)
      const logoFile = rawData.logo;
      if (logoFile && logoFile instanceof File && logoFile.size > 0) {
        data.logoUrl = `[Uploaded: ${logoFile.name}]`;
      }
      // Re-parse formData to get multiple photos
      const formData = await request.clone().formData();
      const photosFiles = formData.getAll('photos') as File[];
      if (photosFiles.length > 0 && photosFiles[0].size > 0) {
        data.photosUrls = `[${photosFiles.length} photo(s) uploaded]`;
      }
    }

    // Save to Google Sheets (initial entry)
    await appendToGoogleSheet(env, data);

    // Send email notifications (if Resend is configured)
    if (env.RESEND_API_KEY) {
      await sendNotificationEmail(env, data);
      await sendCustomerConfirmationEmail(env, data);
    }

    // === AUTOMATION: Create GitHub repo and generate site ===
    // Use waitUntil to run in background so we don't timeout
    console.log('Checking automation prerequisites:', { 
      hasGithubPat: !!env.GITHUB_PAT, 
      hasAnthropicKey: !!env.ANTHROPIC_API_KEY,
      repoName 
    });
    
    if (env.GITHUB_PAT && env.ANTHROPIC_API_KEY) {
      console.log('Starting automation for:', repoName);
      const automationPromise = runAutomation(env, data, templateInfo, repoName, uploadedFiles);
      
      // Use waitUntil if available (Cloudflare Workers), otherwise await
      if (ctx.waitUntil) {
        console.log('Using waitUntil for background processing');
        ctx.waitUntil(automationPromise);
      } else {
        console.log('Awaiting automation directly');
        await automationPromise;
      }
    } else {
      console.log('Automation skipped - missing credentials:', { hasGithubPat: !!env.GITHUB_PAT, hasAnthropicKey: !!env.ANTHROPIC_API_KEY });
    }

    return new Response(JSON.stringify({ success: true, submissionId, repoUrl: data.repoUrl }), {
      status: 200,
      headers,
    });

  } catch (error) {
    console.error('Intake form error:', error);
    return new Response(JSON.stringify({ 
      error: 'Submission failed', 
      details: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers,
    });
  }
};

// Handle OPTIONS for CORS preflight
export const onRequestOptions: PagesFunction = async () => {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
};

// =====================================================
// BACKGROUND AUTOMATION FUNCTION
// =====================================================

async function runAutomation(
  env: Env, 
  data: Record<string, string>, 
  templateInfo: { template: string; tier: string },
  repoName: string,
  uploadedFiles: { key: string; data: ArrayBuffer; contentType: string; filename: string }[]
): Promise<void> {
  console.log('Starting automation for:', repoName, 'template:', templateInfo.template);
  
  try {
    // Step 1: Create repo from template
    const repoResult = await createRepoFromTemplate(env, templateInfo.template, repoName);
    data.repoUrl = repoResult.html_url;
    data.automationStatus = 'repo_created';
    console.log('Step 1 complete: repo created');
    
    // Small delay for GitHub to initialize the repo
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Step 2: Commit customer images to repo
    if (uploadedFiles.length > 0) {
      await commitImagesToRepo(env, repoName, uploadedFiles);
      data.automationStatus = 'images_committed';
    }

    // Step 3: Generate siteConfig.ts using Claude
    const siteConfig = await generateSiteConfig(env, data, templateInfo.tier);
    data.automationStatus = 'config_generated';

    // Step 4: Commit siteConfig.ts to repo
    await commitFileToRepo(env, repoName, 'src/config/siteConfig.ts', siteConfig, 'chore: auto-generate siteConfig from intake form');

    // Step 5: Also commit tailwind.config.cjs with customer colors
    const tailwindConfig = generateTailwindConfig(data);
    await commitFileToRepo(env, repoName, 'tailwind.config.cjs', tailwindConfig, 'chore: apply customer brand colors');
    
    data.automationStatus = 'code_committed';

    // Step 6: Create Cloudflare Pages project (without Git - we'll use direct upload via GitHub Action)
    let projectName = '';
    if (env.CLOUDFLARE_API_TOKEN && env.CLOUDFLARE_ACCOUNT_ID) {
      const pagesResult = await createCloudflarePages(env, repoName);
      data.previewUrl = pagesResult.subdomain;
      projectName = pagesResult.projectName;
      data.automationStatus = 'pages_created';
    }

    // Step 7: Add GitHub Action workflow for auto-deploy to Cloudflare Pages
    if (projectName && env.CLOUDFLARE_API_TOKEN && env.CLOUDFLARE_ACCOUNT_ID) {
      const workflowYaml = generateDeployWorkflow(projectName, env.CLOUDFLARE_ACCOUNT_ID);
      await commitFileToRepo(env, repoName, '.github/workflows/deploy.yml', workflowYaml, 'ci: add Cloudflare Pages deploy workflow');
      
      // The workflow commit will trigger GitHub Actions
      // If org-level CLOUDFLARE_API_TOKEN secret is set, it will auto-deploy
      // Otherwise, the admin needs to add the secret to enable deployments
      
      data.automationStatus = 'workflow_added';
    } else {
      data.automationStatus = 'complete_no_deploy';
    }

    // Update sheet with repo URL and status
    await updateSheetRow(env, data.timestamp, data.repoUrl, data.automationStatus, data.previewUrl);

    // Send success notification
    if (env.RESEND_API_KEY) {
      await sendAutomationSuccessEmail(env, data);
    }

  } catch (automationError) {
    console.error('Automation error:', automationError);
    data.automationStatus = `error: ${automationError instanceof Error ? automationError.message : 'unknown'}`;
    // Update sheet with error status so we can see what happened
    try {
      await updateSheetRow(env, data.timestamp, data.repoUrl || '', data.automationStatus, '');
    } catch (sheetError) {
      console.error('Failed to update sheet with error:', sheetError);
    }
  }
}

// =====================================================
// GOOGLE SHEETS FUNCTIONS  
// =====================================================

// Google Sheets API Integration
async function appendToGoogleSheet(env: Env, data: Record<string, string>) {
  const jwt = await createGoogleJWT(env);
  const accessToken = await getGoogleAccessToken(jwt);

  // Column order: A-U existing fields, V=tier, W=repoUrl, X=automationStatus, Y=previewUrl
  const values = [
    [
      data.timestamp,         // A
      data.businessName,      // B
      data.industry,          // C
      data.serviceArea,       // D
      data.services,          // E
      data.contactName,       // F
      data.email,             // G
      data.phone,             // H
      data.address,           // I
      data.primaryColor,      // J
      data.secondaryColor,    // K
      data.accentColor,       // L
      data.textColor,         // M
      data.domain,            // N
      data.facebook,          // O
      data.instagram,         // P
      data.google,            // Q
      data.yelp,              // R
      data.logoUrl,           // S
      data.photosUrls,        // T
      data.notes,             // U
      data.tier || '',        // V - Tier (starter/professional/medical)
      data.repoUrl || '',     // W - Repo URL
      data.automationStatus || 'pending',  // X - Status
      data.previewUrl || '',  // Y - Preview URL (Cloudflare Pages)
    ],
  ];

  const response = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!A:Y:append?valueInputOption=RAW`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ values }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Google Sheets API error: ${error}`);
  }
}

// Create JWT for Google API authentication
async function createGoogleJWT(env: Env): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  // Import private key and sign
  // Handle various formats of the private key from environment variables:
  // 1. Literal \n characters (from JSON copy/paste)
  // 2. Missing newline after BEGIN header (-----BEGIN PRIVATE KEY-----n instead of newline)
  // 3. Missing newline before END footer
  let privateKey = env.GOOGLE_PRIVATE_KEY;
  
  // Replace literal \n with actual newlines
  if (privateKey.includes('\\n')) {
    privateKey = privateKey.replace(/\\n/g, '\n');
  }
  
  // Fix common copy/paste issue: "-----BEGIN PRIVATE KEY-----n" should have newline not 'n'
  privateKey = privateKey.replace(/-----BEGIN PRIVATE KEY-----n/g, '-----BEGIN PRIVATE KEY-----\n');
  
  // Ensure proper newline before END marker
  privateKey = privateKey.replace(/([A-Za-z0-9+/=])-----END PRIVATE KEY-----/g, '$1\n-----END PRIVATE KEY-----');
  
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signatureInput)
  );

  const encodedSignature = base64UrlEncode(signature);
  return `${signatureInput}.${encodedSignature}`;
}

// Base64 URL encode (handles both strings and ArrayBuffers)
function base64UrlEncode(input: string | ArrayBuffer): string {
  let base64: string;
  if (typeof input === 'string') {
    base64 = btoa(input);
  } else {
    base64 = btoa(String.fromCharCode(...new Uint8Array(input)));
  }
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Convert PEM to ArrayBuffer for crypto API
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Exchange JWT for access token
async function getGoogleAccessToken(jwt: string): Promise<string> {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Google OAuth error: ${error}`);
  }

  const data = await response.json() as { access_token: string };
  return data.access_token;
}

// Send email notification via Resend
async function sendNotificationEmail(env: Env, data: Record<string, string>) {
  const emailBody = `
🎉 New Website Intake Submission!

📍 Business Information
━━━━━━━━━━━━━━━━━━━━━━
Business Name: ${data.businessName}
Industry: ${data.industry}
Service Area: ${data.serviceArea}

📞 Contact
━━━━━━━━━━━━━━━━━━━━━━
Name: ${data.contactName}
Email: ${data.email}
Phone: ${data.phone}
Address: ${data.address || 'Not provided'}

🎨 Branding
━━━━━━━━━━━━━━━━━━━━━━
Primary: ${data.primaryColor}
Secondary: ${data.secondaryColor}
Accent: ${data.accentColor}
Text: ${data.textColor}

🌐 Domain & Social
━━━━━━━━━━━━━━━━━━━━━━
Domain: ${data.domain || 'Needs one'}
Facebook: ${data.facebook || 'Not provided'}
Instagram: ${data.instagram || 'Not provided'}
Google: ${data.google || 'Not provided'}

📁 Files
━━━━━━━━━━━━━━━━━━━━━━
Logo: ${data.logoUrl || 'Not uploaded'}
Photos: ${data.photosUrls || 'None uploaded'}

📝 Services
━━━━━━━━━━━━━━━━━━━━━━
${data.services}

💬 Notes
━━━━━━━━━━━━━━━━━━━━━━
${data.notes || 'None'}

━━━━━━━━━━━━━━━━━━━━━━
Submitted: ${data.timestamp}
`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'GetYours <noreply@indirecttek.com>',
      to: env.NOTIFICATION_EMAIL,
      subject: `🚀 New Intake: ${data.businessName} (${data.industry})`,
      text: emailBody,
    }),
  });
}

// Send confirmation email to customer
async function sendCustomerConfirmationEmail(env: Env, data: Record<string, string>) {
  const emailBody = `
Hi ${data.contactName.split(' ')[0]}!

Thanks for submitting your project details for ${data.businessName}! 🎉

We've received everything and our team is reviewing your information. Here's what happens next:

📋 WHAT WE RECEIVED
━━━━━━━━━━━━━━━━━━━━━━
Business: ${data.businessName}
Industry: ${data.industry}
Service Area: ${data.serviceArea}

🎨 YOUR BRAND COLORS
━━━━━━━━━━━━━━━━━━━━━━
Primary: ${data.primaryColor}
Secondary: ${data.secondaryColor}
Accent: ${data.accentColor}

⏱️ TIMELINE
━━━━━━━━━━━━━━━━━━━━━━
• Within 24-48 hours: We'll review your submission
• Within 3-5 business days: Your first draft will be ready
• You'll receive an email when your site preview is available

💬 QUESTIONS?
━━━━━━━━━━━━━━━━━━━━━━
We're here to help! Contact us anytime:
📧 Email: support@indirecttek.com
🌐 Website: https://indirecttek.com

🛡️ WANT WORRY-FREE MAINTENANCE?
━━━━━━━━━━━━━━━━━━━━━━
Let us handle the technical stuff! Our Care Plan ($49.99/mo) includes:
• Managed hosting & SSL certificate
• Security & performance updates  
• Minor content changes (up to 2/month)
• Priority email support

→ Add Care Plan: https://buy.stripe.com/dRmcN5e209Dy1LV0Fd8IU09
(100% optional. Cancel anytime.)

Thanks for choosing GetYours!

Best,
The IndirectTek Team
`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'GetYours <noreply@indirecttek.com>',
      to: data.email,
      subject: `✅ We received your project details for ${data.businessName}!`,
      text: emailBody,
    }),
  });
}

// =====================================================
// GITHUB AUTOMATION FUNCTIONS
// =====================================================

// Create a new repo from template
async function createRepoFromTemplate(env: Env, templateName: string, newRepoName: string): Promise<{ html_url: string; full_name: string }> {
  console.log('Creating repo from template:', { templateName, newRepoName });
  
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${templateName}/generate`;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.GITHUB_PAT}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'GetYours-Automation',
    },
    body: JSON.stringify({
      owner: GITHUB_OWNER,
      name: newRepoName,
      description: `Auto-generated site from GetYours intake form`,
      private: true, // Keep customer repos private
      include_all_branches: false,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    console.error('GitHub create repo failed:', response.status, error);
    throw new Error(`GitHub create repo failed: ${error}`);
  }

  const result = await response.json() as { html_url: string; full_name: string };
  console.log('Repo created:', result.html_url);
  return result;
}

// Commit a single file to repo
async function commitFileToRepo(env: Env, repoName: string, filePath: string, content: string, message: string): Promise<void> {
  // First, get the current file SHA if it exists (needed for updates)
  let sha: string | undefined;
  
  const getResponse = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${repoName}/contents/${filePath}`, {
    headers: {
      'Authorization': `Bearer ${env.GITHUB_PAT}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'GetYours-Automation',
    },
  });

  if (getResponse.ok) {
    const fileData = await getResponse.json() as { sha: string };
    sha = fileData.sha;
  }

  // Create or update the file
  const response = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${repoName}/contents/${filePath}`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${env.GITHUB_PAT}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'GetYours-Automation',
    },
    body: JSON.stringify({
      message,
      content: btoa(unescape(encodeURIComponent(content))), // Base64 encode content
      sha, // Include sha if updating existing file
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`GitHub commit failed for ${filePath}: ${error}`);
  }
}

// Commit images to repo
async function commitImagesToRepo(env: Env, repoName: string, files: { key: string; data: ArrayBuffer; contentType: string; filename: string }[]): Promise<void> {
  for (const file of files) {
    // Determine target path
    let targetPath: string;
    if (file.key.includes('/logo-')) {
      targetPath = `public/images/logo${file.filename.substring(file.filename.lastIndexOf('.'))}`;
    } else {
      targetPath = `public/images/${file.filename}`;
    }

    // Convert ArrayBuffer to base64
    const base64Content = arrayBufferToBase64(file.data);

    // Commit the file
    const response = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${repoName}/contents/${targetPath}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${env.GITHUB_PAT}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'GetYours-Automation',
      },
      body: JSON.stringify({
        message: `chore: add customer image ${file.filename}`,
        content: base64Content,
      }),
    });

    if (!response.ok) {
      console.error(`Failed to commit image ${file.filename}:`, await response.text());
      // Don't throw - continue with other files
    }
  }
}

// Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// =====================================================
// CLAUDE AI FUNCTIONS
// =====================================================

// Generate siteConfig.ts using Claude
async function generateSiteConfig(env: Env, data: Record<string, string>, tier: string): Promise<string> {
  const prompt = buildSiteConfigPrompt(data, tier);
  
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY!,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Claude API error: ${error}`);
  }

  const result = await response.json() as { content: Array<{ type: string; text: string }> };
  const text = result.content[0]?.text || '';
  
  // Extract the TypeScript code from the response
  const codeMatch = text.match(/```(?:typescript|ts)?\s*([\s\S]*?)```/);
  if (codeMatch) {
    return codeMatch[1].trim();
  }
  
  // If no code block found, return the whole response (Claude might have returned clean code)
  return text.trim();
}

// Build the prompt for Claude
function buildSiteConfigPrompt(data: Record<string, string>, tier: string): string {
  const services = data.services.split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);
  
  return `You are a professional copywriter and web developer. Generate a complete siteConfig.ts file for a ${data.industry} business website.

BUSINESS INFORMATION:
- Business Name: ${data.businessName}
- Industry: ${data.industry}
- Service Area: ${data.serviceArea}
- Contact Name: ${data.contactName}
- Phone: ${data.phone}
- Email: ${data.email}
- Address: ${data.address || 'Not provided'}
- Domain: ${data.domain || 'TBD'}

SERVICES OFFERED:
${services.map((s, i) => `${i + 1}. ${s}`).join('\n')}

BRAND COLORS:
- Primary: ${data.primaryColor}
- Secondary: ${data.secondaryColor}
- Accent: ${data.accentColor}
- Text/Foreground: ${data.textColor}
- Background: #F5F5F5 (light neutral)

SOCIAL MEDIA:
- Facebook: ${data.facebook || 'None'}
- Instagram: ${data.instagram || 'None'}
- Google Business: ${data.google || 'None'}
- Yelp: ${data.yelp || 'None'}

CUSTOMER NOTES:
${data.notes || 'None provided'}

TIER: ${tier} (${tier === 'starter' ? 'service trade' : tier === 'professional' ? 'professional/credentialed' : 'medical/regulated'})

Generate a complete siteConfig.ts file that:
1. Imports the SiteConfig type from "@indirecttek/essentials-engine"
2. Uses compelling, professional headline copy appropriate for the industry
3. Includes 3-4 well-written service descriptions based on the services listed
4. Has proper SEO title and description
5. Uses the exact brand colors provided
6. Includes proper contact information

CRITICAL: Output ONLY the TypeScript code, wrapped in \`\`\`typescript code blocks. No explanations.

Example structure:
\`\`\`typescript
import type { SiteConfig } from "@indirecttek/essentials-engine";

export const siteConfig: SiteConfig = {
  businessName: "...",
  theme: {
    primary: "...",
    secondary: "...",
    accent: "...",
    background: "...",
    foreground: "...",
  },
  contactInfo: {
    phone: "...",
    email: "...",
    address: "...",
  },
  heroSection: {
    headline: "...",
    subheadline: "...",
    imageUrl: "/images/hero.jpg",
    imageAlt: "...",
    callToActionLabel: "...",
  },
  services: [
    { name: "...", description: "..." },
  ],
  analytics: {
    enableTracking: true,
    mixpanelToken: "",
  },
  seo: {
    title: "...",
    description: "...",
  },
  imageSearchHints: {
    hero: "...",
    services: ["..."],
  },
};
\`\`\``;
}

// Generate tailwind.config.cjs with customer colors
function generateTailwindConfig(data: Record<string, string>): string {
  return `/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{astro,html,js,jsx,ts,tsx,vue,svelte}",
    "./node_modules/@indirecttek/essentials-engine/dist/**/*.{astro,html,js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "${data.primaryColor}",
        secondary: "${data.secondaryColor}",
        accent: "${data.accentColor}",
        background: "#F5F5F0",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
`;
}

// =====================================================
// CLOUDFLARE PAGES FUNCTIONS
// =====================================================

// Get the GitHub installation ID from Cloudflare
async function getGitHubInstallationId(env: Env): Promise<number | null> {
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/connections`,
      {
        headers: {
          'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        },
      }
    );

    const responseText = await response.text();
    console.log('GitHub connections response:', responseText);

    if (!response.ok) {
      console.error('Failed to get GitHub connections:', responseText);
      return null;
    }

    const result = JSON.parse(responseText) as {
      success: boolean;
      result?: Array<{ provider: string; id: number; installation_id?: number }>;
    };

    if (!result.success || !result.result || result.result.length === 0) {
      console.error('No connections found in result:', result);
      return null;
    }

    // Find the GitHub connection - check both 'id' and 'installation_id'
    const githubConnection = result.result.find(c => c.provider === 'github');
    if (githubConnection) {
      return githubConnection.installation_id || githubConnection.id || null;
    }
    
    // If no github provider found, just return the first connection's id
    return result.result[0]?.installation_id || result.result[0]?.id || null;
  } catch (error) {
    console.error('Error getting GitHub installation ID:', error);
    return null;
  }
}

// Create a Cloudflare Pages project (without Git connection - we use GitHub Actions instead)
async function createCloudflarePages(env: Env, repoName: string): Promise<{ subdomain: string; projectName: string }> {
  // Create a project name (must be lowercase, alphanumeric, hyphens only)
  const projectName = repoName.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 58);
  
  console.log('Creating Cloudflare Pages project:', projectName);

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/projects`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: projectName,
        production_branch: 'main',
        build_config: {
          build_command: 'npm run build',
          destination_dir: 'dist',
          root_dir: '',
        },
      }),
    }
  );

  const responseText = await response.text();
  console.log('Pages creation response:', responseText);

  if (!response.ok) {
    throw new Error(`Cloudflare Pages creation failed: ${responseText}`);
  }

  const result = JSON.parse(responseText) as { 
    success: boolean; 
    result?: { subdomain: string; name: string };
    errors?: Array<{ message: string }>;
  };
  
  if (!result.success || !result.result) {
    throw new Error(`Cloudflare Pages error: ${result.errors?.[0]?.message || 'Unknown error'}`);
  }

  // Return the preview URL and project name
  return { 
    subdomain: `https://${result.result.subdomain || result.result.name}.pages.dev`,
    projectName: projectName,
  };
}

// Generate GitHub Actions workflow for Cloudflare Pages deployment
function generateDeployWorkflow(projectName: string, accountId: string): string {
  return `name: Deploy to Cloudflare Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      deployments: write
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: \${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${accountId}
          command: pages deploy dist --project-name=${projectName}
`;
}

// Trigger a deployment for a Pages project
async function triggerPagesDeployment(env: Env, projectName: string): Promise<void> {
  // Use the deployments endpoint to trigger a build
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/projects/${projectName}/deployments`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        branch: 'main',
      }),
    }
  );

  if (!response.ok) {
    // Log but don't fail - the project is created, deployment can be triggered later
    console.error('Failed to trigger deployment:', await response.text());
  }
}

// =====================================================
// SHEET UPDATE FUNCTIONS
// =====================================================

// Update a row in the sheet with repo URL, status, and preview URL
async function updateSheetRow(env: Env, timestamp: string, repoUrl: string, status: string, previewUrl?: string): Promise<void> {
  const jwt = await createGoogleJWT(env);
  const accessToken = await getGoogleAccessToken(jwt);

  // First, find the row with this timestamp
  const searchResponse = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!A:A`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!searchResponse.ok) {
    console.error('Failed to search sheet:', await searchResponse.text());
    return;
  }

  const searchData = await searchResponse.json() as { values?: string[][] };
  const rows = searchData.values || [];
  
  // Find the row index (1-based for Sheets API)
  let rowIndex = -1;
  for (let i = 0; i < rows.length; i++) {
    if (rows[i][0] === timestamp) {
      rowIndex = i + 1; // Convert to 1-based
      break;
    }
  }

  if (rowIndex === -1) {
    console.error('Could not find row with timestamp:', timestamp);
    return;
  }

  // Update columns W, X, Y (repoUrl, automationStatus, previewUrl)
  // Note: V=tier (set initially), W=repoUrl, X=automationStatus, Y=previewUrl
  const updateResponse = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!W${rowIndex}:Y${rowIndex}?valueInputOption=RAW`,
    {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        values: [[repoUrl, status, previewUrl || '']],
      }),
    }
  );

  if (!updateResponse.ok) {
    console.error('Failed to update sheet row:', await updateResponse.text());
  }
}

// Send email when automation completes successfully
async function sendAutomationSuccessEmail(env: Env, data: Record<string, string>): Promise<void> {
  const hasPreview = data.previewUrl && data.previewUrl.length > 0;
  const hasWorkflow = data.automationStatus === 'workflow_added';
  
  const emailBody = `
🎉 Website Build Automation Complete!

A new customer site has been automatically generated:

📍 CUSTOMER
━━━━━━━━━━━━━━━━━━━━━━
Business: ${data.businessName}
Contact: ${data.contactName}
Email: ${data.email}
Industry: ${data.industry}
Tier: ${data.tier}

🔧 AUTOMATION COMPLETED
━━━━━━━━━━━━━━━━━━━━━━
✅ Repository created from template
✅ siteConfig.ts generated (Claude AI)
✅ Tailwind brand colors applied
${hasPreview ? `✅ Cloudflare Pages project created` : '⬜ Cloudflare Pages not configured'}
${hasWorkflow ? `✅ GitHub Actions workflow added` : '⬜ No deploy workflow'}

📦 REPOSITORY
━━━━━━━━━━━━━━━━━━━━━━
${data.repoUrl}

${hasPreview ? `🌐 PREVIEW URL (once deployed)
━━━━━━━━━━━━━━━━━━━━━━
${data.previewUrl}
` : ''}
${hasWorkflow ? `🚀 DEPLOYMENT
━━━━━━━━━━━━━━━━━━━━━━
A GitHub Actions workflow has been added to auto-deploy on push.

To enable deployment:
1. Go to: ${data.repoUrl}/settings/secrets/actions
2. Add repository secret: CLOUDFLARE_API_TOKEN
3. Push any change or manually trigger the workflow

OR set up org-level secret at:
https://github.com/organizations/bereizy/settings/secrets/actions
(One time setup - applies to all future repos)
` : ''}
📝 NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━
1. Review the generated siteConfig.ts
2. Check/replace hero image if needed
3. ${hasWorkflow ? 'Add CLOUDFLARE_API_TOKEN secret to trigger deploy' : 'Deploy to Cloudflare Pages manually'}
4. Make any content tweaks - changes auto-deploy!

Status: ${data.automationStatus}
`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'GetYours <noreply@indirecttek.com>',
      to: env.NOTIFICATION_EMAIL,
      subject: `🤖 ${data.businessName} - Site Generated (${data.tier})`,
      text: emailBody,
    }),
  });
}
