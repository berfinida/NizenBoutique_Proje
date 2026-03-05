const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Stripe = require('stripe');
const Iyzipay = require('iyzipay');

const app = express();

const PORT = Number(process.env.PORT || 8787);
const CHECKOUT_AUTH_TOKEN = process.env.CHECKOUT_AUTH_TOKEN || '';
const CHECKOUT_REDIRECT_BASE = process.env.CHECKOUT_REDIRECT_BASE || 'https://pay.example.com/checkout';
const IDEMPOTENCY_TTL_MS = Number(process.env.IDEMPOTENCY_TTL_MS || 20 * 60 * 1000);
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';
const PAYMENT_PROVIDER = (process.env.PAYMENT_PROVIDER || 'mock').toLowerCase();

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_SUCCESS_URL = process.env.STRIPE_SUCCESS_URL || 'http://localhost:8787/success?session_id={CHECKOUT_SESSION_ID}';
const STRIPE_CANCEL_URL = process.env.STRIPE_CANCEL_URL || 'http://localhost:8787/cancel';

const IYZICO_API_KEY = process.env.IYZICO_API_KEY || '';
const IYZICO_SECRET_KEY = process.env.IYZICO_SECRET_KEY || '';
const IYZICO_BASE_URL = process.env.IYZICO_BASE_URL || 'https://sandbox-api.iyzipay.com';
const IYZICO_CALLBACK_URL = process.env.IYZICO_CALLBACK_URL || 'http://localhost:8787/iyzico/callback';

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const iyzico = (IYZICO_API_KEY && IYZICO_SECRET_KEY)
  ? new Iyzipay({ apiKey: IYZICO_API_KEY, secretKey: IYZICO_SECRET_KEY, uri: IYZICO_BASE_URL })
  : null;

app.use(cors({ origin: ALLOW_ORIGIN }));

const idempotencyStore = new Map();
const orderStore = new Map();
const sessionIndex = new Map();

function nowMs() {
  return Date.now();
}

function cleanupExpired() {
  const cutoff = nowMs();
  for (const [key, value] of idempotencyStore.entries()) {
    if (value.expiresAtMs <= cutoff) idempotencyStore.delete(key);
  }
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function assert(condition, status, errorCode, message) {
  if (condition) return;
  const err = new Error(message);
  err.status = status;
  err.errorCode = errorCode;
  throw err;
}

function validateAuth(req) {
  if (!CHECKOUT_AUTH_TOKEN) return;
  const auth = req.get('authorization') || '';
  const expected = `Bearer ${CHECKOUT_AUTH_TOKEN}`;
  assert(auth === expected, 401, 'UNAUTHORIZED', 'Missing or invalid authorization token.');
}

function validatePayload(payload) {
  assert(payload && typeof payload === 'object', 400, 'INVALID_PAYLOAD', 'Payload must be a JSON object.');

  const {
    checkoutVersion,
    createdAt,
    idempotencyKey,
    currency,
    language,
    coupon,
    totals,
    items
  } = payload;

  assert(typeof checkoutVersion === 'string' && checkoutVersion.length >= 4, 400, 'INVALID_PAYLOAD', 'checkoutVersion is required.');
  assert(typeof createdAt === 'string' && !Number.isNaN(Date.parse(createdAt)), 400, 'INVALID_PAYLOAD', 'createdAt must be an ISO date string.');
  assert(typeof idempotencyKey === 'string' && idempotencyKey.length >= 12 && idempotencyKey.length <= 120, 400, 'INVALID_PAYLOAD', 'idempotencyKey is invalid.');
  assert(currency === 'TRY', 422, 'UNSUPPORTED_CURRENCY', 'Only TRY is supported.');
  assert(language === 'tr' || language === 'en', 400, 'INVALID_PAYLOAD', 'language must be tr or en.');
  assert(coupon === null || typeof coupon === 'string', 400, 'INVALID_PAYLOAD', 'coupon must be string or null.');

  assert(totals && typeof totals === 'object', 400, 'INVALID_PAYLOAD', 'totals object is required.');
  const totalKeys = ['subtotal', 'discount', 'discountedSubtotal', 'shipping', 'tax', 'grandTotal'];
  for (const key of totalKeys) {
    assert(isFiniteNumber(totals[key]) && totals[key] >= 0, 400, 'INVALID_PAYLOAD', `totals.${key} must be a non-negative number.`);
  }

  assert(Array.isArray(items) && items.length > 0, 400, 'INVALID_PAYLOAD', 'items must be a non-empty array.');
  let computedSubtotal = 0;
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    assert(item && typeof item === 'object', 400, 'INVALID_PAYLOAD', `items[${i}] must be an object.`);
    assert(Number.isInteger(item.id) && item.id > 0, 400, 'INVALID_PAYLOAD', `items[${i}].id must be a positive integer.`);
    assert(typeof item.name === 'string' && item.name.length > 0, 400, 'INVALID_PAYLOAD', `items[${i}].name is required.`);
    assert(typeof item.size === 'string' && item.size.length > 0, 400, 'INVALID_PAYLOAD', `items[${i}].size is required.`);
    assert(Number.isInteger(item.qty) && item.qty >= 1, 400, 'INVALID_PAYLOAD', `items[${i}].qty must be >= 1.`);
    assert(isFiniteNumber(item.unitPrice) && item.unitPrice >= 0, 400, 'INVALID_PAYLOAD', `items[${i}].unitPrice must be >= 0.`);
    assert(isFiniteNumber(item.lineTotal) && item.lineTotal >= 0, 400, 'INVALID_PAYLOAD', `items[${i}].lineTotal must be >= 0.`);

    const expectedLineTotal = item.qty * item.unitPrice;
    assert(Math.abs(expectedLineTotal - item.lineTotal) < 0.5, 422, 'PRICE_MISMATCH', `items[${i}] line total mismatch.`);
    computedSubtotal += expectedLineTotal;
  }

  assert(Math.abs(computedSubtotal - totals.subtotal) < 0.5, 422, 'PRICE_MISMATCH', 'subtotal mismatch.');
  assert(Math.abs((totals.subtotal - totals.discount) - totals.discountedSubtotal) < 0.5, 422, 'TOTAL_MISMATCH', 'discountedSubtotal mismatch.');
  assert(Math.abs((totals.discountedSubtotal + totals.shipping + totals.tax) - totals.grandTotal) < 0.5, 422, 'TOTAL_MISMATCH', 'grandTotal mismatch.');

  return payload;
}

function buildMockSession(payload) {
  const sessionId = `cs_${crypto.randomUUID().replace(/-/g, '')}`;
  const expiresAtMs = nowMs() + IDEMPOTENCY_TTL_MS;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const checkoutToken = Buffer.from(
    JSON.stringify({
      sessionId,
      idempotencyKey: payload.idempotencyKey,
      createdAt: payload.createdAt,
      grandTotal: payload.totals.grandTotal,
      currency: payload.currency
    }),
    'utf8'
  ).toString('base64url');
  const redirectUrl = `${CHECKOUT_REDIRECT_BASE.replace(/\/$/, '')}/${sessionId}?token=${encodeURIComponent(checkoutToken)}`;
  return { sessionId, redirectUrl, expiresAt, expiresAtMs, provider: 'mock' };
}

async function createStripeSession(payload) {
  assert(stripe, 500, 'PROVIDER_NOT_CONFIGURED', 'Stripe provider is not configured.');
  const amount = Math.round(payload.totals.grandTotal * 100);
  assert(amount > 0, 422, 'TOTAL_MISMATCH', 'Grand total must be greater than zero.');

  const session = await stripe.checkout.sessions.create(
    {
      mode: 'payment',
      success_url: STRIPE_SUCCESS_URL,
      cancel_url: STRIPE_CANCEL_URL,
      currency: 'try',
      line_items: [
        {
          price_data: {
            currency: 'try',
            unit_amount: amount,
            product_data: { name: 'NIZEN STORE Order' }
          },
          quantity: 1
        }
      ],
      metadata: {
        idempotencyKey: payload.idempotencyKey,
        checkoutVersion: payload.checkoutVersion,
        language: payload.language,
        coupon: payload.coupon || ''
      }
    },
    { idempotencyKey: payload.idempotencyKey }
  );

  const expiresAtMs = (session.expires_at || Math.floor(nowMs() / 1000) + 1800) * 1000;
  return {
    sessionId: session.id,
    redirectUrl: session.url,
    expiresAt: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
    provider: 'stripe'
  };
}

function createIyzicoSession(payload) {
  return new Promise((resolve, reject) => {
    assert(iyzico, 500, 'PROVIDER_NOT_CONFIGURED', 'iyzico provider is not configured.');

    const grandTotal = payload.totals.grandTotal.toFixed(2);
    const basketItems = payload.items.map((item) => ({
      id: String(item.id),
      name: `${item.name} (${item.size})`,
      category1: 'Apparel',
      itemType: Iyzipay.BASKET_ITEM_TYPE.PHYSICAL,
      price: item.lineTotal.toFixed(2)
    }));

    const req = {
      locale: payload.language === 'en' ? Iyzipay.LOCALE.EN : Iyzipay.LOCALE.TR,
      conversationId: payload.idempotencyKey,
      price: grandTotal,
      paidPrice: grandTotal,
      currency: Iyzipay.CURRENCY.TRY,
      basketId: payload.idempotencyKey,
      paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
      callbackUrl: IYZICO_CALLBACK_URL,
      enabledInstallments: [1],
      buyer: {
        id: 'guest-user',
        name: 'Guest',
        surname: 'User',
        gsmNumber: '+905000000000',
        email: 'guest@example.com',
        identityNumber: '11111111111',
        registrationAddress: 'Nizen Store HQ',
        ip: '127.0.0.1',
        city: 'Istanbul',
        country: 'Turkey',
        zipCode: '34000'
      },
      shippingAddress: {
        contactName: 'Guest User',
        city: 'Istanbul',
        country: 'Turkey',
        address: 'Nizen Store HQ',
        zipCode: '34000'
      },
      billingAddress: {
        contactName: 'Guest User',
        city: 'Istanbul',
        country: 'Turkey',
        address: 'Nizen Store HQ',
        zipCode: '34000'
      },
      basketItems
    };

    iyzico.checkoutFormInitialize.create(req, (err, result) => {
      if (err) return reject(err);
      if (!result || result.status !== 'success') {
        const failure = new Error(result && result.errorMessage ? result.errorMessage : 'iyzico session failed');
        failure.status = 502;
        failure.errorCode = 'PROVIDER_ERROR';
        return reject(failure);
      }
      const expiresAtMs = nowMs() + IDEMPOTENCY_TTL_MS;
      return resolve({
        sessionId: result.token || payload.idempotencyKey,
        redirectUrl: result.paymentPageUrl,
        expiresAt: new Date(expiresAtMs).toISOString(),
        expiresAtMs,
        provider: 'iyzico'
      });
    });
  });
}

async function createProviderSession(payload) {
  if (PAYMENT_PROVIDER === 'stripe') return createStripeSession(payload);
  if (PAYMENT_PROVIDER === 'iyzico') return createIyzicoSession(payload);
  return buildMockSession(payload);
}

function upsertPendingOrder(payload, session) {
  const nowIso = new Date().toISOString();
  const order = {
    idempotencyKey: payload.idempotencyKey,
    provider: session.provider,
    providerSessionId: session.sessionId,
    redirectUrl: session.redirectUrl,
    status: 'pending_payment',
    createdAt: nowIso,
    updatedAt: nowIso,
    payload
  };
  orderStore.set(payload.idempotencyKey, order);
  sessionIndex.set(session.sessionId, payload.idempotencyKey);
  return order;
}

function setOrderStatusByIdempotency(idempotencyKey, status, metadata = {}) {
  const order = orderStore.get(idempotencyKey);
  if (!order) return null;
  order.status = status;
  order.updatedAt = new Date().toISOString();
  order.metadata = { ...(order.metadata || {}), ...metadata };
  orderStore.set(idempotencyKey, order);
  return order;
}

function setOrderStatusBySession(sessionId, status, metadata = {}) {
  const idempotencyKey = sessionIndex.get(sessionId);
  if (!idempotencyKey) return null;
  return setOrderStatusByIdempotency(idempotencyKey, status, metadata);
}

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res, next) => {
  try {
    assert(stripe, 500, 'PROVIDER_NOT_CONFIGURED', 'Stripe provider is not configured.');
    assert(STRIPE_WEBHOOK_SECRET, 500, 'PROVIDER_NOT_CONFIGURED', 'STRIPE_WEBHOOK_SECRET is missing.');
    const sig = req.get('stripe-signature');
    assert(sig, 400, 'INVALID_SIGNATURE', 'Missing stripe-signature header.');

    const event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    const obj = event.data && event.data.object ? event.data.object : {};

    if (event.type === 'checkout.session.completed') {
      setOrderStatusBySession(obj.id, 'paid', { stripePaymentStatus: obj.payment_status || 'paid' });
    } else if (event.type === 'checkout.session.expired') {
      setOrderStatusBySession(obj.id, 'expired');
    } else if (event.type === 'checkout.session.async_payment_failed') {
      setOrderStatusBySession(obj.id, 'payment_failed');
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    return next(error);
  }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'checkout-api',
    provider: PAYMENT_PROVIDER,
    now: new Date().toISOString()
  });
});

app.get('/api/orders/:idempotencyKey', (req, res) => {
  validateAuth(req);
  const order = orderStore.get(req.params.idempotencyKey);
  if (!order) return res.status(404).json({ errorCode: 'ORDER_NOT_FOUND', message: 'Order not found.' });
  return res.status(200).json(order);
});

app.get('/api/orders/session/:sessionId', (req, res) => {
  validateAuth(req);
  const idempotencyKey = sessionIndex.get(req.params.sessionId);
  if (!idempotencyKey) return res.status(404).json({ errorCode: 'ORDER_NOT_FOUND', message: 'Order not found.' });
  const order = orderStore.get(idempotencyKey);
  if (!order) return res.status(404).json({ errorCode: 'ORDER_NOT_FOUND', message: 'Order not found.' });
  return res.status(200).json(order);
});

app.post('/webhooks/iyzico', (req, res, next) => {
  try {
    const conversationId = req.body.conversationId || req.body.idempotencyKey || '';
    const token = req.body.token || req.body.paymentToken || '';
    const statusRaw = String(req.body.status || req.body.paymentStatus || '').toLowerCase();

    const inferredStatus =
      statusRaw === 'success' || statusRaw === 'paid' ? 'paid'
        : statusRaw === 'failure' || statusRaw === 'failed' ? 'payment_failed'
          : 'pending_payment';

    let order = null;
    if (conversationId) order = setOrderStatusByIdempotency(conversationId, inferredStatus, { iyzicoRawStatus: statusRaw, token });
    if (!order && token) order = setOrderStatusBySession(token, inferredStatus, { iyzicoRawStatus: statusRaw, token });

    return res.status(200).json({ received: true, updated: !!order });
  } catch (error) {
    return next(error);
  }
});

app.post('/iyzico/callback', (req, res, next) => {
  try {
    const token = req.body.token;
    const conversationId = req.body.conversationId;
    if (!token || !iyzico) return res.status(200).send('ok');

    iyzico.checkoutForm.retrieve({ token, conversationId: conversationId || '' }, (err, result) => {
      if (err) return next(err);
      const paid = result && result.paymentStatus && String(result.paymentStatus).toUpperCase() === 'SUCCESS';
      const status = paid ? 'paid' : 'payment_failed';
      let order = null;
      if (conversationId) order = setOrderStatusByIdempotency(conversationId, status, { iyzicoVerified: true, token });
      if (!order) order = setOrderStatusBySession(token, status, { iyzicoVerified: true, token });
      return res.status(200).send('ok');
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/checkout/session', async (req, res, next) => {
  try {
    cleanupExpired();
    validateAuth(req);
    const payload = validatePayload(req.body);

    const existing = idempotencyStore.get(payload.idempotencyKey);
    if (existing && existing.expiresAtMs > nowMs()) {
      const existingOrder = orderStore.get(payload.idempotencyKey) || upsertPendingOrder(payload, existing);
      return res.status(200).json({
        sessionId: existing.sessionId,
        redirectUrl: existing.redirectUrl,
        expiresAt: existing.expiresAt,
        provider: existing.provider,
        orderStatus: existingOrder.status
      });
    }

    const session = await createProviderSession(payload);
    idempotencyStore.set(payload.idempotencyKey, session);
    const order = upsertPendingOrder(payload, session);

    return res.status(200).json({
      sessionId: session.sessionId,
      redirectUrl: session.redirectUrl,
      expiresAt: session.expiresAt,
      provider: session.provider,
      orderStatus: order.status
    });
  } catch (error) {
    return next(error);
  }
});

app.use((err, req, res, next) => {
  const status = err.status || 500;
  const errorCode = err.errorCode || 'INTERNAL_ERROR';
  const message = err.message || 'Unexpected server error.';
  if (status >= 500) console.error(err);
  res.status(status).json({ errorCode, message });
});

app.listen(PORT, () => {
  console.log(`Checkout API listening on http://localhost:${PORT} (provider=${PAYMENT_PROVIDER})`);
});
