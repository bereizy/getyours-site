// Cloudflare Pages Function - verifies Stripe session and returns tier info
// Called from thank-you page to get a secure token for the intake form

interface Env {
  STRIPE_SECRET_KEY?: string;
}

// Map Stripe price IDs to tiers
const PRICE_TO_TIER: Record<string, string> = {
  // Starter Tier ($699) - with and without care plan
  'price_starter': 'starter',
  'price_starter_care': 'starter',
  // Professional Tier ($1,499)
  'price_professional': 'professional', 
  'price_professional_care': 'professional',
  // Medical Tier ($3,999)
  'price_medical': 'medical',
  'price_medical_care': 'medical',
};

// Fallback: Map product names/descriptions to tiers
function getTierFromProduct(productName: string): string {
  const name = productName.toLowerCase();
  if (name.includes('medical') || name.includes('dental') || name.includes('practice')) {
    return 'medical';
  }
  if (name.includes('professional') || name.includes('1499') || name.includes('1,499')) {
    return 'professional';
  }
  if (name.includes('starter') || name.includes('landscaper') || name.includes('699')) {
    return 'starter';
  }
  return 'starter'; // Default fallback
}

export const onRequestGet: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session_id');

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  if (!sessionId) {
    return new Response(JSON.stringify({ error: 'Missing session_id' }), {
      status: 400,
      headers,
    });
  }

  // For development/testing: allow a bypass token
  if (sessionId === 'dev_test_starter') {
    return new Response(JSON.stringify({ 
      valid: true, 
      tier: 'starter',
      token: generateToken('starter'),
    }), { headers });
  }
  if (sessionId === 'dev_test_professional') {
    return new Response(JSON.stringify({ 
      valid: true, 
      tier: 'professional',
      token: generateToken('professional'),
    }), { headers });
  }
  if (sessionId === 'dev_test_medical') {
    return new Response(JSON.stringify({ 
      valid: true, 
      tier: 'medical',
      token: generateToken('medical'),
    }), { headers });
  }

  // Verify with Stripe
  if (!env.STRIPE_SECRET_KEY) {
    // If no Stripe key configured, allow through for testing
    console.log('No STRIPE_SECRET_KEY configured, allowing session');
    return new Response(JSON.stringify({ 
      valid: true, 
      tier: 'starter',
      token: generateToken('starter'),
      warning: 'Stripe not configured',
    }), { headers });
  }

  try {
    // Fetch session from Stripe
    const stripeResponse = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${sessionId}?expand[]=line_items`,
      {
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        },
      }
    );

    if (!stripeResponse.ok) {
      return new Response(JSON.stringify({ 
        error: 'Invalid session',
        valid: false,
      }), { status: 400, headers });
    }

    const session = await stripeResponse.json() as {
      payment_status: string;
      line_items?: {
        data: Array<{
          price?: { id: string };
          description?: string;
        }>;
      };
    };

    // Check payment was successful
    if (session.payment_status !== 'paid') {
      return new Response(JSON.stringify({ 
        error: 'Payment not completed',
        valid: false,
      }), { status: 400, headers });
    }

    // Determine tier from line items
    let tier = 'starter';
    if (session.line_items?.data) {
      for (const item of session.line_items.data) {
        if (item.price?.id && PRICE_TO_TIER[item.price.id]) {
          tier = PRICE_TO_TIER[item.price.id];
          break;
        }
        if (item.description) {
          tier = getTierFromProduct(item.description);
          break;
        }
      }
    }

    return new Response(JSON.stringify({ 
      valid: true,
      tier,
      token: generateToken(tier),
    }), { headers });

  } catch (error) {
    console.error('Stripe verification error:', error);
    return new Response(JSON.stringify({ 
      error: 'Verification failed',
      valid: false,
    }), { status: 500, headers });
  }
};

// Generate a simple token encoding the tier and timestamp
// In production, you'd want to use a proper JWT or signed token
function generateToken(tier: string): string {
  const data = {
    tier,
    exp: Date.now() + (24 * 60 * 60 * 1000), // 24 hour expiry
  };
  // Simple base64 encoding - not cryptographically secure but prevents casual tampering
  // For production, sign this with a secret key
  return btoa(JSON.stringify(data));
}

export const onRequestOptions: PagesFunction = async () => {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
};
