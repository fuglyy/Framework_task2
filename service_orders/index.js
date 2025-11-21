const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const z = require('zod');
const pino = require('pino');
const axios = require('axios');
const EventEmitter = require('events');

const app = express();
const PORT = process.env.PORT || 8002;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const USERS_ENDPOINT = process.env.USERS_SERVICE_URL || 'http://service_users:8001';

const eventBus = new EventEmitter();

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

eventBus.on('order.created', (order) => {
  logger.info({ orderId: order.id, userId: order.userId }, 'Event: order.created');
});
eventBus.on('order.status.updated', (order) => {
  logger.info({ orderId: order.id, status: order.status }, 'Event: order.status.updated');
});

app.use(cors());
app.use(express.json());

// request id
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  logger.info({ rid: req.id, method: req.method, url: req.url }, 'Req received');
  next();
});

// store
let ordersStore = {};

// schemas
const itemSchema = z.object({
  product: z.string().min(1),
  quantity: z.number().int().positive()
});
const createOrderSchema = z.object({
  userId: z.string().uuid(),
  items: z.array(itemSchema).min(1),
  totalAmount: z.number().positive()
});
const updateStatusSchema = z.object({
  status: z.enum(['created', 'in_progress', 'completed', 'cancelled'])
});

// auth middleware
const authGuard = (req, res, next) => {
  const ah = req.headers?.authorization;
  if (!ah?.startsWith('Bearer ')) {
    logger.warn({ rid: req.id }, 'No auth header');
    return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authorization token required' } });
  }
  const token = ah.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    logger.info({ rid: req.id, userId: payload.userId }, 'User validated');
    next();
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Token invalid');
    return res.status(401).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' } });
  }
};

// helper — checks user exists by calling users service internal API
const doesUserExist = async (userId) => {
  try {
    const resp = await axios.get(`${USERS_ENDPOINT}/api/v1/users/${userId}`, { timeout: 2000 });
    return resp.data?.success === true;
  } catch (err) {
    logger.error({ userId, err: err.message }, 'User existence check failed');
    return false;
  }
};

// create order
app.post('/api/v1/orders', authGuard, async (req, res) => {
  try {
    const parsed = createOrderSchema.safeParse(req.body);
    if (!parsed.success) {
      logger.warn({ rid: req.id, errors: parsed.error.errors }, 'Order validation failed');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: parsed.error.errors[0].message } });
    }

    const { userId, items, totalAmount } = parsed.data;
    if (req.user.userId !== userId && !req.user.roles.includes('admin')) {
      logger.warn({ rid: req.id, userId, requester: req.user.userId }, 'Unauthorized order creation');
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Cannot create order for another user' } });
    }

    const userExists = await doesUserExist(userId);
    if (!userExists) {
      return res.status(400).json({ success: false, error: { code: 'USER_NOT_FOUND', message: 'User does not exist' } });
    }

    const id = uuidv4();
    const now = new Date().toISOString();
    const newOrder = {
      id,
      userId,
      items,
      status: 'created',
      totalAmount,
      createdAt: now,
      updatedAt: now
    };

    ordersStore[id] = newOrder;
    logger.info({ rid: req.id, orderId: id, userId }, 'Order created');

    eventBus.emit('order.created', newOrder);
    return res.status(201).json({ success: true, data: newOrder });
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Order creation error');
    return res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  }
});

// get order
app.get('/api/v1/orders/:orderId', authGuard, (req, res) => {
  const order = ordersStore[req.params.orderId];
  if (!order) return res.status(404).json({ success: false, error: { code: 'ORDER_NOT_FOUND', message: 'Order not found' } });

  if (order.userId !== req.user.userId && !req.user.roles.includes('admin')) {
    logger.warn({ rid: req.id, userId: req.user.userId }, 'Unauthorized order access');
    return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
  }

  logger.info({ rid: req.id, orderId: order.id }, 'Order returned');
  return res.json({ success: true, data: order });
});

// list orders
app.get('/api/v1/orders', authGuard, (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const sortBy = req.query.sortBy || 'createdAt';
  const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
  const statusFilter = req.query.status;

  let list = Object.values(ordersStore);

  if (!req.user.roles.includes('admin')) {
    list = list.filter(o => o.userId === req.user.userId);
  }

  if (statusFilter) list = list.filter(o => o.status === statusFilter);

  list.sort((a, b) => {
    if (a[sortBy] < b[sortBy]) return -sortOrder;
    if (a[sortBy] > b[sortBy]) return sortOrder;
    return 0;
  });

  const start = (page - 1) * limit;
  const pageItems = list.slice(start, start + limit);

  logger.info({ rid: req.id, page, limit, total: list.length }, 'Orders page returned');
  return res.json({
    success: true,
    data: {
      orders: pageItems,
      pagination: { page, limit, total: list.length, totalPages: Math.ceil(list.length / limit) }
    }
  });
});

// update status
app.put('/api/v1/orders/:orderId/status', authGuard, (req, res) => {
  try {
    const parsed = updateStatusSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: parsed.error.errors[0].message } });
    }

    const order = ordersStore[req.params.orderId];
    if (!order) return res.status(404).json({ success: false, error: { code: 'ORDER_NOT_FOUND', message: 'Order not found' } });

    if (order.userId !== req.user.userId && !req.user.roles.includes('admin')) {
      logger.warn({ rid: req.id, userId: req.user.userId }, 'Unauthorized status update');
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
    }

    const updated = { ...order, status: parsed.data.status, updatedAt: new Date().toISOString() };
    ordersStore[req.params.orderId] = updated;

    logger.info({ rid: req.id, orderId: order.id, newStatus: parsed.data.status }, 'Order status updated');
    eventBus.emit('order.status.updated', updated);

    return res.json({ success: true, data: updated });
  } catch (err) {
    logger.error({ rid: req.id, err: err.message }, 'Status update error');
    return res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  }
});

// cancel (delete)
app.delete('/api/v1/orders/:orderId', authGuard, (req, res) => {
  const order = ordersStore[req.params.orderId];
  if (!order) return res.status(404).json({ success: false, error: { code: 'ORDER_NOT_FOUND', message: 'Order not found' } });

  if (order.userId !== req.user.userId && !req.user.roles.includes('admin')) {
    logger.warn({ rid: req.id, userId: req.user.userId }, 'Unauthorized cancel');
    return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
  }

  if (order.status === 'completed') {
    return res.status(400).json({ success: false, error: { code: 'CANNOT_CANCEL', message: 'Cannot cancel completed order' } });
  }

  const cancelled = { ...order, status: 'cancelled', updatedAt: new Date().toISOString() };
  ordersStore[req.params.orderId] = cancelled;
  logger.info({ rid: req.id, orderId: order.id }, 'Order cancelled');

  eventBus.emit('order.status.updated', cancelled);
  return res.json({ success: true, data: { message: 'Order cancelled', order: cancelled } });
});

// health
app.get('/health', (req, res) => {
  return res.json({ success: true, data: { status: 'healthy', service: 'orders-service', timestamp: new Date().toISOString() } });
});

// boot
app.listen(PORT, '0.0.0.0', () => {
  logger.info({ port: PORT }, 'Orders service up');
});
