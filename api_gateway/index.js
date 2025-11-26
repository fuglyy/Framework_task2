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

const USERS_ENDPOINT = process.env.USERS_SERVICE_URL || 'http://service_users:8001';
const ORDERS_ENDPOINT = process.env.ORDERS_SERVICE_URL || 'http://service_orders:8002';

// Logger
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

app.use(express.json());
app.use(cors({ origin: '*', credentials: true, exposedHeaders: ['X-Request-ID'] }));

// Unified error format helper
function errorPayload(code, message) {
  return { success: false, error: { code, message } };
}

// Assign X-Request-ID
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true
}));

const authAttemptsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50
});

// JWT middleware
const checkAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json(errorPayload('UNAUTHORIZED', 'Authorization token required'));

  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json(errorPayload('INVALID_TOKEN', 'Invalid or expired token'));
  }
};

// Universal proxy with REAL error handling
async function forward(baseUrl, req, res) {
  const cfg = {
    method: req.method,
    url: `${baseUrl}${req.path}`,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': req.id,
      ...(req.headers.authorization ? { Authorization: req.headers.authorization } : {})
    },
    params: req.query,
    timeout: 5000
  };

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) cfg.data = req.body;

  try {
    const serviceResp = await axios(cfg);
    return res.status(serviceResp.status).json(serviceResp.data);
  } catch (err) {
    // 1) SERVICE ANSWERED WITH AN ERROR (like 400 / 401 / 403 / 404 / 409)
    if (err.response) {
      return res.status(err.response.status).json(
        err.response.data?.error
          ? err.response.data // { success:false, error:{...} }
          : errorPayload('SERVICE_ERROR', 'Service returned an error')
      );
    }

    // 2) TIMEOUT / CONNECTION REFUSED → REAL SERVICE DOWN
    return res.status(503).json(
      errorPayload(
        'SERVICE_UNAVAILABLE',
        `${baseUrl.includes('users') ? 'Users' : 'Orders'} service is temporarily unavailable`
      )
    );
  }
}

// AUTH
app.post('/api/v1/auth/register', authAttemptsLimiter, (req, res) =>
  forward(USERS_ENDPOINT, req, res)
);

app.post('/api/v1/auth/login', authAttemptsLimiter, (req, res) =>
  forward(USERS_ENDPOINT, req, res)
);

// USERS
app.get('/api/v1/users/profile', checkAuth, (req, res) =>
  forward(USERS_ENDPOINT, req, res)
);

app.put('/api/v1/users/profile', checkAuth, (req, res) =>
  forward(USERS_ENDPOINT, req, res)
);

app.get('/api/v1/users', checkAuth, (req, res) =>
  forward(USERS_ENDPOINT, req, res)
);

// ORDERS
app.post('/api/v1/orders', checkAuth, (req, res) =>
  forward(ORDERS_ENDPOINT, req, res)
);

app.get('/api/v1/orders/:orderId', checkAuth, (req, res) =>
  forward(ORDERS_ENDPOINT, req, res)
);

app.get('/api/v1/orders', checkAuth, (req, res) =>
  forward(ORDERS_ENDPOINT, req, res)
);

app.put('/api/v1/orders/:orderId/status', checkAuth, (req, res) =>
  forward(ORDERS_ENDPOINT, req, res)
);

app.delete('/api/v1/orders/:orderId', checkAuth, (req, res) =>
  forward(ORDERS_ENDPOINT, req, res)
);

// HEALTH
app.get('/health', async (req, res) => {
  const data = {
    status: 'healthy',
    services: { gateway: 'ok', users: 'ok', orders: 'ok' }
  };

  try {
    await axios.get(`${USERS_ENDPOINT}/health`, { timeout: 1500 });
  } catch {
    data.status = 'degraded';
    data.services.users = 'down';
  }

  try {
    await axios.get(`${ORDERS_ENDPOINT}/health`, { timeout: 1500 });
  } catch {
    data.status = 'degraded';
    data.services.orders = 'down';
  }

  res.status(data.status === 'healthy' ? 200 : 503).json({ success: true, data });
});

// 404
app.use((req, res) =>
  res.status(404).json(errorPayload('NOT_FOUND', 'Route not found'))
);

// 500 fallback
app.use((err, req, res, next) =>
  res.status(500).json(errorPayload('INTERNAL_ERROR', 'Internal server error'))
);

app.listen(PORT, () =>
  logger.info({ port: PORT }, 'Gateway running')
);
