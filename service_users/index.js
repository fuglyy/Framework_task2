const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const z = require('zod');
const pino = require('pino');

const app = express();
const PORT = process.env.PORT || 8001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// logger with different message wording
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

app.use(cors());
app.use(express.json());

// request id middleware
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  logger.info({ rid: req.id, method: req.method, url: req.url }, 'Req received');
  next();
});

// in-memory store (same semantics)
let usersStore = {};

// validation (same rules but variable names changed)
const schemas = {
  register: z.object({
    email: z.string().email(),
    password: z.string().min(6),
    name: z.string().min(2)
  }),
  login: z.object({
    email: z.string().email(),
    password: z.string().min(1)
  }),
  updateProfile: z.object({
    name: z.string().min(2).optional(),
    email: z.string().email().optional()
  })
};

// helper for consistent responses
function successPayload(payload) {
  return { success: true, data: payload };
}
function errorPayload(code, message) {
  return { success: false, error: { code, message } };
}

// auth middleware (renamed to authGuard)
const authGuard = (req, res, next) => {
  const tokenHeader = req.headers?.authorization;
  if (!tokenHeader?.startsWith('Bearer ')) {
    logger.warn({ rid: req.id }, 'No auth header');
    return res.status(401).json(errorPayload('UNAUTHORIZED', 'Authorization token required'));
  }

  const token = tokenHeader.slice(7);
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    req.user = claims;
    logger.info({ rid: req.id, userId: claims.userId }, 'User authenticated');
    return next();
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Invalid token');
    return res.status(401).json(errorPayload('INVALID_TOKEN', 'Invalid or expired token'));
  }
};

// role-checker middleware (kept behavior)
const hasRole = (...roles) => (req, res, next) => {
  if (!req.user || !req.user.roles || !req.user.roles.some(r => roles.includes(r))) {
    logger.warn({ rid: req.id, userId: req.user?.userId, required: roles }, 'Access denied');
    return res.status(403).json(errorPayload('FORBIDDEN', 'Insufficient permissions'));
  }
  next();
};

// Routes

// register
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const parsed = schemas.register.safeParse(req.body);
    if (!parsed.success) {
      logger.warn({ rid: req.id, errors: parsed.error.errors }, 'Register validation failed');
      return res.status(400).json(errorPayload('VALIDATION_ERROR', parsed.error.errors[0].message));
    }

    const { email, password, name } = parsed.data;
    // check existing
    const exists = Object.values(usersStore).some(u => u.email === email);
    if (exists) {
      logger.warn({ rid: req.id, email }, 'User exists');
      return res.status(400).json(errorPayload('USER_EXISTS', 'User with this email already exists'));
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const now = new Date().toISOString();

    usersStore[id] = {
      id,
      email,
      passwordHash,
      name,
      roles: ['user'],
      createdAt: now,
      updatedAt: now
    };

    logger.info({ rid: req.id, userId: id }, 'User created');

    const { passwordHash: _, ...safeUser } = usersStore[id];
    return res.status(201).json(successPayload(safeUser));
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Register failed');
    return res.status(500).json(errorPayload('INTERNAL_ERROR', 'Internal server error'));
  }
});

// login
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const parsed = schemas.login.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json(errorPayload('VALIDATION_ERROR', parsed.error.errors[0].message));
    }

    const { email, password } = parsed.data;
    const user = Object.values(usersStore).find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      logger.warn({ rid: req.id, email }, 'Bad credentials');
      return res.status(401).json(errorPayload('INVALID_CREDENTIALS', 'Invalid email or password'));
    }

    const token = jwt.sign({ userId: user.id, email: user.email, roles: user.roles }, JWT_SECRET, { expiresIn: '24h' });
    logger.info({ rid: req.id, userId: user.id }, 'User logged in');

    return res.json(successPayload({
      token,
      user: { id: user.id, email: user.email, name: user.name, roles: user.roles }
    }));
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Login failed');
    return res.status(500).json(errorPayload('INTERNAL_ERROR', 'Internal server error'));
  }
});

// profile read
app.get('/api/v1/users/profile', authGuard, (req, res) => {
  const user = usersStore[req.user.userId];
  if (!user) {
    return res.status(404).json(errorPayload('USER_NOT_FOUND', 'User not found'));
  }
  const { passwordHash, ...out } = user;
  logger.info({ rid: req.id, userId: user.id }, 'Profile delivered');
  return res.json(successPayload(out));
});

// profile update
app.put('/api/v1/users/profile', authGuard, async (req, res) => {
  try {
    const parsed = schemas.updateProfile.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json(errorPayload('VALIDATION_ERROR', parsed.error.errors[0].message));
    }

    const user = usersStore[req.user.userId];
    if (!user) {
      return res.status(404).json(errorPayload('USER_NOT_FOUND', 'User not found'));
    }

    if (parsed.data.email && parsed.data.email !== user.email) {
      const other = Object.values(usersStore).find(u => u.email === parsed.data.email);
      if (other) {
        return res.status(400).json(errorPayload('EMAIL_TAKEN', 'Email already in use'));
      }
    }

    const updated = { ...user, ...parsed.data, updatedAt: new Date().toISOString() };
    usersStore[user.id] = updated;
    const { passwordHash, ...safe } = updated;
    logger.info({ rid: req.id, userId: user.id }, 'Profile updated');
    return res.json(successPayload(safe));
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Profile update error');
    return res.status(500).json(errorPayload('INTERNAL_ERROR', 'Internal server error'));
  }
});

// admin users list (kept behavior)
app.get('/api/v1/users', authGuard, hasRole('admin'), (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const roleFilter = req.query.role;

  let list = Object.values(usersStore).map(({ passwordHash, ...rest }) => rest);

  if (roleFilter) list = list.filter(u => u.roles.includes(roleFilter));

  const start = (page - 1) * limit;
  const pageSlice = list.slice(start, start + limit);

  logger.info({ rid: req.id, page, limit, total: list.length }, 'Users page delivered');
  return res.json(successPayload({
    users: pageSlice,
    pagination: {
      page,
      limit,
      total: list.length,
      totalPages: Math.ceil(list.length / limit)
    }
  }));
});

// internal, no auth: get user by id
app.get('/api/v1/users/:userId', (req, res) => {
  const u = usersStore[req.params.userId];
  if (!u) return res.status(404).json(errorPayload('USER_NOT_FOUND', 'User not found'));
  const { passwordHash, ...safe } = u;
  return res.json(successPayload(safe));
});

// health
app.get('/health', (req, res) => {
  return res.json({
    success: true,
    data: { status: 'healthy', service: 'users-service', timestamp: new Date().toISOString() }
  });
});

// Start server and seed admin (kept same credentials for tests)
app.listen(PORT, '0.0.0.0', () => {
  logger.info({ port: PORT }, 'Users service up');

  const adminId = uuidv4();
  const now = new Date().toISOString();
  bcrypt.hash('admin123', 10).then(hash => {
    usersStore[adminId] = {
      id: adminId,
      email: 'admin@example.com',
      passwordHash: hash,
      name: 'Admin User',
      roles: ['admin', 'user'],
      createdAt: now,
      updatedAt: now
    };
    logger.info('Admin user created: admin@example.com / admin123');
  }).catch(err => {
    logger.error({ err: err.message }, 'Failed creating admin');
  });
});
