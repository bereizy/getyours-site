// Cloudflare Pages Function - handles /api/intake POST requests
// Saves data to Google Sheets, sends email notification

interface Env {
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string;
  GOOGLE_PRIVATE_KEY: string;
  GOOGLE_SHEET_ID: string;
  NOTIFICATION_EMAIL: string;
  RESEND_API_KEY?: string;
  R2_BUCKET?: R2Bucket;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  try {
    const formData = await request.formData();
    const timestamp = new Date().toISOString();

    // Extract form fields
    const data: Record<string, string> = {
      timestamp,
      businessName: (formData.get('businessName') as string) || '',
      industry: (formData.get('industry') as string) || '',
      serviceArea: (formData.get('serviceArea') as string) || '',
      services: (formData.get('services') as string) || '',
      contactName: (formData.get('contactName') as string) || '',
      email: (formData.get('email') as string) || '',
      phone: (formData.get('phone') as string) || '',
      address: (formData.get('address') as string) || '',
      primaryColor: (formData.get('primaryColor') as string) || '',
      secondaryColor: (formData.get('secondaryColor') as string) || '',
      accentColor: (formData.get('accentColor') as string) || '',
      textColor: (formData.get('textColor') as string) || '',
      domain: (formData.get('domain') as string) || '',
      facebook: (formData.get('facebook') as string) || '',
      instagram: (formData.get('instagram') as string) || '',
      google: (formData.get('google') as string) || '',
      yelp: (formData.get('yelp') as string) || '',
      logoUrl: '',
      photosUrls: '',
      notes: (formData.get('notes') as string) || '',
    };

    // Generate unique submission ID
    const submissionId = `${Date.now()}-${data.businessName.replace(/\s+/g, '-').toLowerCase()}`;

    // Handle file uploads to R2 if available
    if (env.R2_BUCKET) {
      const logoFile = formData.get('logo') as File | null;
      if (logoFile && logoFile.size > 0) {
        const logoKey = `submissions/${submissionId}/logo-${logoFile.name}`;
        await env.R2_BUCKET.put(logoKey, await logoFile.arrayBuffer(), {
          httpMetadata: { contentType: logoFile.type },
        });
        data.logoUrl = logoKey;
      }

      const photosFiles = formData.getAll('photos') as File[];
      const photoKeys: string[] = [];
      for (const photo of photosFiles) {
        if (photo && photo.size > 0) {
          const photoKey = `submissions/${submissionId}/photos/${photo.name}`;
          await env.R2_BUCKET.put(photoKey, await photo.arrayBuffer(), {
            httpMetadata: { contentType: photo.type },
          });
          photoKeys.push(photoKey);
        }
      }
      data.photosUrls = photoKeys.join('\n');
    } else {
      // No R2 - note file upload status
      const logoFile = formData.get('logo') as File | null;
      if (logoFile && logoFile.size > 0) {
        data.logoUrl = `[Uploaded: ${logoFile.name}]`;
      }
      const photosFiles = formData.getAll('photos') as File[];
      if (photosFiles.length > 0 && photosFiles[0].size > 0) {
        data.photosUrls = `[${photosFiles.length} photo(s) uploaded]`;
      }
    }

    // Save to Google Sheets
    await appendToGoogleSheet(env, data);

    // Send email notification (if Resend is configured)
    if (env.RESEND_API_KEY) {
      await sendNotificationEmail(env, data);
    }

    return new Response(JSON.stringify({ success: true, submissionId }), {
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

// Google Sheets API Integration
async function appendToGoogleSheet(env: Env, data: Record<string, string>) {
  const jwt = await createGoogleJWT(env);
  const accessToken = await getGoogleAccessToken(jwt);

  const values = [
    [
      data.timestamp,
      data.businessName,
      data.industry,
      data.serviceArea,
      data.services,
      data.contactName,
      data.email,
      data.phone,
      data.address,
      data.primaryColor,
      data.secondaryColor,
      data.accentColor,
      data.textColor,
      data.domain,
      data.facebook,
      data.instagram,
      data.google,
      data.yelp,
      data.logoUrl,
      data.photosUrls,
      data.notes,
    ],
  ];

  const response = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!A:U:append?valueInputOption=RAW`,
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
      from: 'IndirectTek <noreply@indirecttek.com>',
      to: env.NOTIFICATION_EMAIL,
      subject: `🚀 New Intake: ${data.businessName} (${data.industry})`,
      text: emailBody,
    }),
  });
}
