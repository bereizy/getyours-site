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

    // Step 6: Create Cloudflare Pages project
    let projectName = '';
    if (env.CLOUDFLARE_API_TOKEN && env.CLOUDFLARE_ACCOUNT_ID) {
      const pagesResult = await createCloudflarePages(env, repoName);
      data.previewUrl = pagesResult.subdomain;
      projectName = pagesResult.projectName;
      data.automationStatus = 'pages_created';
    }

    // Step 7: Trigger the centralized deployer workflow
    // This builds and deploys the site via bereizy/site-deployer GitHub Action
    if (projectName) {
      await triggerDeployerWorkflow(env, repoName, projectName);
      data.automationStatus = 'deploy_triggered';
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
// STOCK IMAGE URLS BY INDUSTRY
// =====================================================

// Get industry-specific stock image URLs from Unsplash
function getIndustryImageUrls(industry: string): { hero: string; about: string } {
  // Using Unsplash Source for reliable, high-quality stock images
  // Format: https://images.unsplash.com/photo-ID?w=1200&h=800&fit=crop
  
  const imageMap: Record<string, { hero: string; about: string }> = {
    // Starter Tier - Service Trades
    'landscaping': {
      hero: 'https://images.unsplash.com/photo-1558904541-efa843a96f01?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1592417817098-8fd3d9eb14a5?w=800&h=600&fit=crop',
    },
    'pressure-washing': {
      hero: 'https://images.unsplash.com/photo-1581578731548-c64695cc6952?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1628177142898-93e36e4e3a50?w=800&h=600&fit=crop',
    },
    'auto-detailing': {
      hero: 'https://images.unsplash.com/photo-1607860108855-64acf2078ed9?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1520340356584-f9917d1eea6f?w=800&h=600&fit=crop',
    },
    'home-cleaning': {
      hero: 'https://images.unsplash.com/photo-1581578731548-c64695cc6952?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1527515545081-5db817172677?w=800&h=600&fit=crop',
    },
    'handyman': {
      hero: 'https://images.unsplash.com/photo-1504148455328-c376907d081c?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1621905251189-08b45d6a269e?w=800&h=600&fit=crop',
    },
    'junk-removal': {
      hero: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1532996122724-e3c354a0b15b?w=800&h=600&fit=crop',
    },
    'pool-cleaning': {
      hero: 'https://images.unsplash.com/photo-1576013551627-0cc20b96c2a7?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1572331165267-854da2b021aa?w=800&h=600&fit=crop',
    },
    'painting': {
      hero: 'https://images.unsplash.com/photo-1562259929-b4e1fd3aef09?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1589939705384-5185137a7f0f?w=800&h=600&fit=crop',
    },
    
    // Professional Tier
    'real-estate': {
      hero: 'https://images.unsplash.com/photo-1560518883-ce09059eeffa?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1560520653-9e0e4c89eb11?w=800&h=600&fit=crop',
    },
    'tax-accounting': {
      hero: 'https://images.unsplash.com/photo-1554224155-6726b3ff858f?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1450101499163-c8848c66ca85?w=800&h=600&fit=crop',
    },
    'consulting': {
      hero: 'https://images.unsplash.com/photo-1552664730-d307ca884978?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1542744173-8e7e53415bb0?w=800&h=600&fit=crop',
    },
    'insurance': {
      hero: 'https://images.unsplash.com/photo-1450101499163-c8848c66ca85?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=800&h=600&fit=crop',
    },
    'legal': {
      hero: 'https://images.unsplash.com/photo-1589829545856-d10d557cf95f?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1505664194779-8beaceb93744?w=800&h=600&fit=crop',
    },
    'photography': {
      hero: 'https://images.unsplash.com/photo-1542038784456-1ea8e935640e?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1471341971476-ae15ff5dd4ea?w=800&h=600&fit=crop',
    },
    'salon': {
      hero: 'https://images.unsplash.com/photo-1560066984-138dadb4c035?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1522337360788-8b13dee7a37e?w=800&h=600&fit=crop',
    },
    'fitness': {
      hero: 'https://images.unsplash.com/photo-1534438327276-14e5300c3a48?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1571902943202-507ec2618e8f?w=800&h=600&fit=crop',
    },
    'tech-repair': {
      hero: 'https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1588508065123-287b28e013da?w=800&h=600&fit=crop',
    },
    
    // Medical Tier
    'dental': {
      hero: 'https://images.unsplash.com/photo-1606811841689-23dfddce3e95?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1588776814546-1ffcf47267a5?w=800&h=600&fit=crop',
    },
    'medical': {
      hero: 'https://images.unsplash.com/photo-1519494026892-80bbd2d6fd0d?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1504439468489-c8920d796a29?w=800&h=600&fit=crop',
    },
    'chiropractic': {
      hero: 'https://images.unsplash.com/photo-1544161515-4ab6ce6db874?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1519823551278-64ac92734fb1?w=800&h=600&fit=crop',
    },
    'therapy': {
      hero: 'https://images.unsplash.com/photo-1573497620053-ea5300f94f21?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1527689368864-3a821dbccc34?w=800&h=600&fit=crop',
    },
    'optometry': {
      hero: 'https://images.unsplash.com/photo-1574258495973-f010dfbb5371?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1591076482161-42ce6da69f67?w=800&h=600&fit=crop',
    },
    'veterinary': {
      hero: 'https://images.unsplash.com/photo-1628009368231-7bb7cfcb0def?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1612531386530-97286d97c2d2?w=800&h=600&fit=crop',
    },
    'medical-aesthetics': {
      hero: 'https://images.unsplash.com/photo-1570172619644-dfd03ed5d881?w=1200&h=800&fit=crop',
      about: 'https://images.unsplash.com/photo-1629909613654-28e377c37b09?w=800&h=600&fit=crop',
    },
  };
  
  // Default fallback for 'other' or unknown industries
  const defaultImages = {
    hero: 'https://images.unsplash.com/photo-1497366216548-37526070297c?w=1200&h=800&fit=crop',
    about: 'https://images.unsplash.com/photo-1497366811353-6870744d04b2?w=800&h=600&fit=crop',
  };
  
  return imageMap[industry] || defaultImages;
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
  
  // Get placeholder image URLs based on industry
  const imageUrls = getIndustryImageUrls(data.industry);
  
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

IMAGE URLs TO USE (these are pre-selected stock photos - use them exactly):
- Hero image: "${imageUrls.hero}"
- About section: "${imageUrls.about}"

Generate a complete siteConfig.ts file that:
1. Imports the SiteConfig type from "@indirecttek/essentials-engine"
2. Uses compelling, professional headline copy appropriate for the industry
3. Includes 3-4 well-written service descriptions based on the services listed
4. Has proper SEO title and description
5. Uses the exact brand colors provided
6. Includes proper contact information
7. Uses the exact imageUrl values provided above for heroSection.imageUrl

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

// Trigger the centralized site-deployer workflow to build and deploy
const DEPLOYER_REPO = 'site-deployer';

async function triggerDeployerWorkflow(env: Env, repoName: string, projectName: string): Promise<void> {
  console.log('Triggering deployer workflow for:', repoName, projectName);
  
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${DEPLOYER_REPO}/actions/workflows/deploy-site.yml/dispatches`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.GITHUB_PAT}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'GetYours-Automation',
      },
      body: JSON.stringify({
        ref: 'main',
        inputs: {
          repo_name: repoName,
          project_name: projectName,
        },
      }),
    }
  );

  // GitHub returns 204 No Content on success for workflow_dispatch
  const responseText = await response.text();
  console.log('Deployer workflow response:', response.status, responseText || '(empty body)');
  
  if (!response.ok) {
    console.error('Failed to trigger deployer workflow:', response.status, responseText);
    // Don't throw - site is created, just not auto-deployed
  } else {
    console.log('Deployer workflow triggered successfully, status:', response.status);
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
  const deployTriggered = data.automationStatus === 'deploy_triggered';
  
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
${deployTriggered ? `✅ Build & deploy triggered` : '⬜ Deploy not triggered'}

📦 REPOSITORY
━━━━━━━━━━━━━━━━━━━━━━
${data.repoUrl}

${hasPreview ? `🌐 PREVIEW URL
━━━━━━━━━━━━━━━━━━━━━━
${data.previewUrl}

${deployTriggered ? `🚀 DEPLOYING NOW!
The site is being built and deployed automatically.
It should be live within 2-3 minutes!` : 'Deploy was not triggered automatically.'}
` : ''}
📝 NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━
${deployTriggered ? `1. Wait 2-3 minutes for build to complete
2. Visit ${data.previewUrl} to see the live site
3. Review and make any content tweaks in the repo
4. Future pushes will auto-deploy!` : `1. Review the generated siteConfig.ts
2. Deploy manually or check GitHub Actions`}

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
