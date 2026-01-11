// Cloudflare Pages Function - handles Stripe webhook events
// Logs payments to Google Sheets

interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string;
  GOOGLE_PRIVATE_KEY: string;
  GOOGLE_SHEET_ID: string;
  RESEND_API_KEY?: string;
  NOTIFICATION_EMAIL: string;
}

interface StripeEvent {
  id: string;
  type: string;
  data: {
    object: {
      id: string;
      amount_total: number;
      currency: string;
      customer_email: string;
      customer_details?: {
        email: string;
        name: string;
      };
      metadata?: Record<string, string>;
      payment_status: string;
      status: string;
    };
  };
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  try {
    const payload = await request.text();
    const signature = request.headers.get('stripe-signature');

    if (!signature) {
      return new Response('Missing signature', { status: 400 });
    }

    // Verify webhook signature
    const isValid = await verifyStripeSignature(payload, signature, env.STRIPE_WEBHOOK_SECRET);
    if (!isValid) {
      return new Response('Invalid signature', { status: 400 });
    }

    const event: StripeEvent = JSON.parse(payload);

    // Handle checkout.session.completed event
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      
      if (session.payment_status === 'paid') {
        const timestamp = new Date().toISOString();
        const amount = (session.amount_total / 100).toFixed(2);
        const customerEmail = session.customer_details?.email || session.customer_email || 'Unknown';
        const customerName = session.customer_details?.name || 'Unknown';
        
        // Determine tier based on amount
        let tier = 'Unknown';
        if (session.amount_total === 69900) tier = 'Starter ($699)';
        else if (session.amount_total === 149900) tier = 'Professional ($1,499)';
        else if (session.amount_total === 399900) tier = 'Medical ($3,999)';
        else tier = `Custom ($${amount})`;

        // Log to Google Sheets (Payments tab)
        await logPaymentToSheet(env, {
          timestamp,
          stripeSessionId: session.id,
          customerName,
          customerEmail,
          tier,
          amount: `$${amount}`,
          currency: session.currency.toUpperCase(),
          status: 'Paid',
        });

        // Send notification email
        if (env.RESEND_API_KEY) {
          await sendPaymentNotification(env, {
            customerName,
            customerEmail,
            tier,
            amount: `$${amount}`,
            timestamp,
          });
        }
      }
    }

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Webhook error:', error);
    return new Response(JSON.stringify({ error: 'Webhook processing failed' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

// Verify Stripe webhook signature
async function verifyStripeSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const parts = signature.split(',');
  const timestampPart = parts.find(p => p.startsWith('t='));
  const signaturePart = parts.find(p => p.startsWith('v1='));

  if (!timestampPart || !signaturePart) return false;

  const timestamp = timestampPart.split('=')[1];
  const expectedSignature = signaturePart.split('=')[1];

  // Check if timestamp is within 5 minutes
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) return false;

  // Compute expected signature
  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signatureBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
  const computedSignature = Array.from(new Uint8Array(signatureBytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return computedSignature === expectedSignature;
}

// Log payment to Google Sheets
async function logPaymentToSheet(env: Env, data: Record<string, string>) {
  const jwt = await createGoogleJWT(env);
  const accessToken = await getGoogleAccessToken(jwt);

  const values = [[
    data.timestamp,
    data.stripeSessionId,
    data.customerName,
    data.customerEmail,
    data.tier,
    data.amount,
    data.currency,
    data.status,
  ]];

  // Append to "Payments" sheet
  const response = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Payments!A:H:append?valueInputOption=USER_ENTERED`,
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

// Create JWT for Google API
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

  // Handle various formats of private key
  let privateKey = env.GOOGLE_PRIVATE_KEY;
  if (privateKey.includes('\\n')) {
    privateKey = privateKey.replace(/\\n/g, '\n');
  }
  privateKey = privateKey.replace(/-----BEGIN PRIVATE KEY-----n/g, '-----BEGIN PRIVATE KEY-----\n');
  privateKey = privateKey.replace(/([A-Za-z0-9+/=])-----END PRIVATE KEY-----/g, '$1\n-----END PRIVATE KEY-----');

  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(signatureInput));
  const encodedSignature = base64UrlEncode(signature);

  return `${signatureInput}.${encodedSignature}`;
}

async function getGoogleAccessToken(jwt: string): Promise<string> {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  if (!response.ok) {
    throw new Error(`Google OAuth error: ${await response.text()}`);
  }

  const data = await response.json() as { access_token: string };
  return data.access_token;
}

function base64UrlEncode(data: string | ArrayBuffer): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Send payment notification email
async function sendPaymentNotification(env: Env, data: Record<string, string>) {
  const emailBody = `
💰 NEW PAYMENT RECEIVED!
━━━━━━━━━━━━━━━━━━━━━━

Customer: ${data.customerName}
Email: ${data.customerEmail}
Tier: ${data.tier}
Amount: ${data.amount}
Time: ${data.timestamp}

The customer will be redirected to the intake form next.
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
      subject: `💰 Payment: ${data.tier} from ${data.customerName}`,
      text: emailBody,
    }),
  });
}
