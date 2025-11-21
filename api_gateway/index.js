const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const pino = require('pino');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Endpoints (small rename for stylistic difference)
const USERS_ENDPOINT = process.env.USERS_SERVICE_URL || 'http://service_users:8001';
const ORDERS_ENDPOINT = process.env.ORDERS_SERVICE_URL || 'http://service_orders:8002';

// Logger (messages phrased differently)
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname'
    }
  }
});

// --- middleware setup (order intentionally changed) ---
app.use(express.json());

const corsCfg = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true,
  exposedHeaders: ['X-Request-ID']
};
app.use(cors(corsCfg));

// tiny helper to build consistent error payloads
function errorPayload(code, message) {
  return {
    success: false,
    error: { code, message }
  };
}

// Request id + lightweight request logger
app.use((req, res, next) => {
  const rid = req.headers['x-request-id'] || uuidv4();
  req.id = rid;
  res.setHeader('X-Request-ID', rid);

  logger.info({ rid, method: req.method, path: req.path }, 'Request received');
  next();
});

// Global rate limiter (kept semantically same but renamed variable)
const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ rid: req.id, ip: req.ip }, 'Rate limit hit');
    res.status(429).json(errorPayload('RATE_LIMIT_EXCEEDED', 'Too many requests, please try again later'));
  }
});
app.use(globalLimit);

// Stricter auth attempts limiter
const authAttemptsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  handler: (req, res) => {
    logger.warn({ rid: req.id }, 'Auth rate limit');
    res.status(429).json(errorPayload('AUTH_RATE_LIMIT_EXCEEDED', 'Too many authentication attempts, please try again later'));
  }
});

// Auth middleware (renamed and written with optional chaining)
const checkAuth = (req, res, next) => {
  const authHeader = req.headers?.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    logger.warn({ rid: req.id }, 'Auth header missing/invalid');
    return res.status(401).json(errorPayload('UNAUTHORIZED', 'Authorization token required'));
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    logger.info({ rid: req.id, userId: payload.userId }, 'Token validated');
    return next();
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Token invalid/expired');
    return res.status(401).json(errorPayload('INVALID_TOKEN', 'Invalid or expired token'));
  }
};

// Proxy helper (kept behavior same)
const forwardTo = async (baseUrl, req) => {
  const headers = {
    'Content-Type': 'application/json',
    'X-Request-ID': req.id
  };
  if (req.headers?.authorization) headers.Authorization = req.headers.authorization;

  const cfg = {
    method: req.method,
    url: `${baseUrl}${req.path}`,
    headers,
    params: req.query,
    timeout: 5000
  };

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) cfg.data = req.body;

  logger.info({ rid: req.id, target: cfg.url }, 'Forwarding request');
  return axios(cfg);
};

// --- Public auth routes ---
app.post('/api/v1/auth/register', authAttemptsLimiter, async (req, res) => {
  try {
    const resp = await forwardTo(USERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Register proxy failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Users service is temporarily unavailable'));
  }
});

app.post('/api/v1/auth/login', authAttemptsLimiter, async (req, res) => {
  try {
    const resp = await forwardTo(USERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Login proxy failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Users service is temporarily unavailable'));
  }
});

// --- Protected user routes ---
app.get('/api/v1/users/profile', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(USERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Users service error');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Users service is temporarily unavailable'));
  }
});

app.put('/api/v1/users/profile', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(USERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Users update failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Users service is temporarily unavailable'));
  }
});

app.get('/api/v1/users', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(USERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Users list failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Users service is temporarily unavailable'));
  }
});

// --- Orders routes (protected) ---
app.post('/api/v1/orders', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(ORDERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Orders service failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Orders service is temporarily unavailable'));
  }
});

app.get('/api/v1/orders/:orderId', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(ORDERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Order fetch failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Orders service is temporarily unavailable'));
  }
});

app.get('/api/v1/orders', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(ORDERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Orders list failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Orders service is temporarily unavailable'));
  }
});

app.put('/api/v1/orders/:orderId/status', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(ORDERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Orders status update failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Orders service is temporarily unavailable'));
  }
});

app.delete('/api/v1/orders/:orderId', checkAuth, async (req, res) => {
  try {
    const resp = await forwardTo(ORDERS_ENDPOINT, req);
    return res.status(resp.status).json(resp.data);
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Orders delete failed');
    return res.status(503).json(errorPayload('SERVICE_UNAVAILABLE', 'Orders service is temporarily unavailable'));
  }
});

// Healthcheck - slightly different shape but same semantic fields
app.get('/health', async (req, res) => {
  const services = { gateway: 'ok', users: 'unknown', orders: 'unknown' };

  try {
    await axios.get(`${USERS_ENDPOINT}/health`, { timeout: 2000 });
    services.users = 'ok';
  } catch (e) {
    services.users = 'down';
    logger.error({ err: e.message }, 'Users health probe failed');
  }

  try {
    await axios.get(`${ORDERS_ENDPOINT}/health`, { timeout: 2000 });
    services.orders = 'ok';
  } catch (e) {
    services.orders = 'down';
    logger.error({ err: e.message }, 'Orders health probe failed');
  }

  const healthy = services.users === 'ok' && services.orders === 'ok';
  return res.status(healthy ? 200 : 503).json({
    success: healthy,
    data: {
      status: healthy ? 'healthy' : 'degraded',
      services,
      timestamp: new Date().toISOString()
    }
  });
});

// 404 fallback
app.use((req, res) => {
  logger.warn({ rid: req.id, url: req.url }, 'Unknown route');
  return res.status(404).json(errorPayload('NOT_FOUND', 'Route not found'));
});

// generic error handler
app.use((err, req, res, next) => {
  logger.error({ rid: req.id, err: err?.message || String(err), stack: err?.stack }, 'Unhandled error');
  return res.status(500).json(errorPayload('INTERNAL_ERROR', 'Internal server error'));
});

app.listen(PORT, () => {
  logger.info({ port: PORT }, 'API Gateway listening');
});
