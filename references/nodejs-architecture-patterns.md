# Node.js Architecture Patterns for Backend Development

Architectural patterns and structures for building scalable, maintainable Node.js backend applications.

---

## 1. Layered Architecture

### Standard Directory Structure

```
backend/
├── src/
│   ├── controllers/          # HTTP request handlers
│   ├── services/             # Business logic
│   ├── repositories/         # Data access layer
│   ├── models/               # Data models/entities
│   ├── middleware/           # Express/Fastify middleware
│   ├── routes/               # Route definitions
│   ├── validators/           # Input validation schemas
│   ├── utils/                # Utility functions
│   ├── config/               # Configuration management
│   ├── types/                # TypeScript type definitions
│   ├── errors/               # Custom error classes
│   ├── jobs/                 # Background job definitions
│   └── app.ts                # Application setup
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── scripts/                  # Build/migration scripts
├── docs/                     # API documentation
├── .env.example
├── tsconfig.json
└── package.json
```

### Layer Responsibilities

#### Controllers Layer
- Handle HTTP requests/responses
- Validate request data
- Call service methods
- Transform responses
- **NO business logic**

```typescript
// src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/user.service';
import { CreateUserSchema } from '../validators/user.validator';

export class UserController {
  constructor(private userService: UserService) {}

  async createUser(req: Request, res: Response, next: NextFunction) {
    try {
      // Validate input
      const validatedData = CreateUserSchema.parse(req.body);

      // Call service
      const result = await this.userService.createUser(validatedData);

      // Handle result
      if (result.ok) {
        res.status(201).json({ data: result.value });
      } else {
        next(result.error);
      }
    } catch (error) {
      next(error);
    }
  }

  async getUser(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const result = await this.userService.getUserById(id);

      if (result.ok) {
        res.json({ data: result.value });
      } else {
        next(result.error);
      }
    } catch (error) {
      next(error);
    }
  }
}
```

#### Services Layer
- Business logic
- Orchestrate multiple repositories
- Implement domain rules
- Return Result types

```typescript
// src/services/user.service.ts
import { Result, ok, err } from 'neverthrow';
import { UserRepository } from '../repositories/user.repository';
import { EmailService } from './email.service';
import { User, CreateUserInput, AppError } from '../types';

export class UserService {
  constructor(
    private userRepo: UserRepository,
    private emailService: EmailService,
    private logger: Logger
  ) {}

  async createUser(data: CreateUserInput): Promise<Result<User, AppError>> {
    // Check business rules
    const existing = await this.userRepo.findByEmail(data.email);
    if (existing) {
      return err(new ValidationError('Email already exists', { email: 'Duplicate' }));
    }

    // Validate business constraints
    if (data.age < 18) {
      return err(new ValidationError('User must be 18 or older', { age: 'Too young' }));
    }

    // Create user
    const user = await this.userRepo.create(data);

    // Trigger side effects
    await this.emailService.sendWelcomeEmail(user).catch(error => {
      this.logger.error('Failed to send welcome email', error);
    });

    return ok(user);
  }

  async getUserById(id: string): Promise<Result<User, AppError>> {
    const user = await this.userRepo.findById(id);

    if (!user) {
      return err(new NotFoundError('User', id));
    }

    return ok(user);
  }
}
```

#### Repository Layer
- Data access only
- Database queries
- ORM/query builder usage
- **NO business logic**

```typescript
// src/repositories/user.repository.ts
import { Pool } from 'pg';
import { User, CreateUserInput } from '../types';

export class UserRepository {
  constructor(private db: Pool) {}

  async findById(id: string): Promise<User | null> {
    const result = await this.db.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    return result.rows[0] || null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const result = await this.db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    return result.rows[0] || null;
  }

  async create(data: CreateUserInput): Promise<User> {
    const result = await this.db.query(
      `INSERT INTO users (id, name, email, age, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       RETURNING *`,
      [crypto.randomUUID(), data.name, data.email, data.age]
    );

    return result.rows[0];
  }

  async update(id: string, data: Partial<User>): Promise<User | null> {
    const fields = Object.keys(data)
      .map((key, idx) => `${key} = $${idx + 2}`)
      .join(', ');

    const values = [id, ...Object.values(data)];

    const result = await this.db.query(
      `UPDATE users SET ${fields}, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      values
    );

    return result.rows[0] || null;
  }
}
```

---

## 2. Database Transaction Patterns

### Transaction Management

```typescript
// src/services/order.service.ts
import { Pool, PoolClient } from 'pg';

export class OrderService {
  constructor(private db: Pool) {}

  async createOrderWithItems(
    userId: string,
    items: OrderItem[]
  ): Promise<Result<Order, AppError>> {
    const client = await this.db.connect();

    try {
      // Start transaction
      await client.query('BEGIN');

      // Create order
      const orderResult = await client.query(
        `INSERT INTO orders (id, user_id, total, status, created_at)
         VALUES ($1, $2, $3, 'pending', NOW())
         RETURNING *`,
        [crypto.randomUUID(), userId, calculateTotal(items)]
      );
      const order = orderResult.rows[0];

      // Create order items
      for (const item of items) {
        await client.query(
          `INSERT INTO order_items (id, order_id, product_id, quantity, price)
           VALUES ($1, $2, $3, $4, $5)`,
          [crypto.randomUUID(), order.id, item.productId, item.quantity, item.price]
        );

        // Update inventory
        await client.query(
          `UPDATE products
           SET stock = stock - $1
           WHERE id = $2`,
          [item.quantity, item.productId]
        );
      }

      // Commit transaction
      await client.query('COMMIT');

      return ok(order);
    } catch (error) {
      // Rollback on error
      await client.query('ROLLBACK');
      return err(new DatabaseError(error));
    } finally {
      // Always release client
      client.release();
    }
  }
}
```

### Transaction Helper Pattern

```typescript
// src/utils/transaction.ts
import { Pool, PoolClient } from 'pg';

export async function withTransaction<T>(
  pool: Pool,
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// Usage
const order = await withTransaction(db, async (client) => {
  const orderResult = await client.query(/* ... */);
  const order = orderResult.rows[0];

  for (const item of items) {
    await client.query(/* ... */);
  }

  return order;
});
```

---

## 3. Background Job Processing

### Bull Queue Pattern

```typescript
// src/jobs/email.job.ts
import Queue from 'bull';
import { logger } from '../utils/logger';

interface EmailJobData {
  to: string;
  subject: string;
  body: string;
  template?: string;
}

// Create queue
export const emailQueue = new Queue<EmailJobData>('email', {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
  },
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 2000,
    },
    removeOnComplete: true,
    removeOnFail: false,
  },
});

// Process jobs
emailQueue.process(async (job) => {
  const { to, subject, body, template } = job.data;

  logger.info('Processing email job', {
    jobId: job.id,
    to,
    subject,
  });

  try {
    await sendEmail({ to, subject, body, template });

    logger.info('Email sent successfully', { jobId: job.id });
  } catch (error) {
    logger.error('Failed to send email', error, { jobId: job.id });
    throw error; // Will retry based on attempts
  }
});

// Add job to queue
export async function queueEmail(data: EmailJobData) {
  await emailQueue.add(data, {
    priority: data.template === 'password-reset' ? 1 : 5,
    delay: 0,
  });
}

// Job events
emailQueue.on('completed', (job) => {
  logger.info('Email job completed', { jobId: job.id });
});

emailQueue.on('failed', (job, error) => {
  logger.error('Email job failed', error, { jobId: job?.id });
});

emailQueue.on('stalled', (job) => {
  logger.warn('Email job stalled', { jobId: job.id });
});
```

### Advanced Queue Patterns

```typescript
// src/jobs/index.ts
import Queue from 'bull';
import { logger } from '../utils/logger';

// Multiple queues for different priorities
export const highPriorityQueue = new Queue('high-priority', {
  redis: redisConfig,
  settings: {
    maxStalledCount: 3,
    stalledInterval: 30000,
  },
});

export const lowPriorityQueue = new Queue('low-priority', {
  redis: redisConfig,
  settings: {
    maxStalledCount: 1,
    stalledInterval: 60000,
  },
});

// Scheduled jobs (cron)
export const reportQueue = new Queue('reports', { redis: redisConfig });

// Generate daily report at 2 AM
reportQueue.add(
  'daily-report',
  { type: 'daily' },
  {
    repeat: {
      cron: '0 2 * * *',
      tz: 'America/New_York',
    },
  }
);

// Delayed jobs
export async function scheduleNotification(
  userId: string,
  message: string,
  delayMinutes: number
) {
  await highPriorityQueue.add(
    'notification',
    { userId, message },
    {
      delay: delayMinutes * 60 * 1000,
    }
  );
}

// Job chaining
export async function processOrderWorkflow(orderId: string) {
  // Step 1: Validate order
  const validateJob = await highPriorityQueue.add('validate-order', { orderId });

  await validateJob.finished(); // Wait for completion

  // Step 2: Process payment
  const paymentJob = await highPriorityQueue.add('process-payment', { orderId });

  await paymentJob.finished();

  // Step 3: Ship order
  await lowPriorityQueue.add('ship-order', { orderId });
}
```

### Job Worker Setup

```typescript
// src/workers/index.ts
import { emailQueue } from '../jobs/email.job';
import { reportQueue } from '../jobs/report.job';
import { logger } from '../utils/logger';

// Start all workers
export function startWorkers() {
  logger.info('Starting background workers');

  // Email worker
  emailQueue.process(5, async (job) => {
    // Process up to 5 concurrent jobs
    return processEmailJob(job);
  });

  // Report worker
  reportQueue.process(async (job) => {
    return processReportJob(job);
  });

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    logger.info('Shutting down workers');

    await emailQueue.close();
    await reportQueue.close();

    process.exit(0);
  });
}
```

---

## 4. Real-time Patterns (WebSockets)

### Socket.io with Express

```typescript
// src/app.ts
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { setupSocketHandlers } from './sockets';

const app = express();
const httpServer = createServer(app);

// Setup Socket.io
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL,
    credentials: true,
  },
  pingTimeout: 60000,
});

// Authentication middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const user = await verifyToken(token);
    socket.data.user = user;
    next();
  } catch (error) {
    next(new Error('Authentication failed'));
  }
});

// Setup handlers
setupSocketHandlers(io);

export { app, httpServer, io };
```

### Socket Event Handlers

```typescript
// src/sockets/index.ts
import { Server, Socket } from 'socket.io';
import { logger } from '../utils/logger';

interface ServerToClientEvents {
  'message:new': (data: { message: Message }) => void;
  'user:typing': (data: { userId: string; isTyping: boolean }) => void;
  'notification': (data: { type: string; message: string }) => void;
}

interface ClientToServerEvents {
  'message:send': (data: { content: string; roomId: string }) => void;
  'typing:start': (data: { roomId: string }) => void;
  'typing:stop': (data: { roomId: string }) => void;
  'room:join': (data: { roomId: string }) => void;
  'room:leave': (data: { roomId: string }) => void;
}

export function setupSocketHandlers(
  io: Server<ClientToServerEvents, ServerToClientEvents>
) {
  io.on('connection', (socket) => {
    const user = socket.data.user;

    logger.info('User connected', { userId: user.id, socketId: socket.id });

    // Join user's personal room
    socket.join(`user:${user.id}`);

    // Handle room joining
    socket.on('room:join', async ({ roomId }) => {
      // Check authorization
      const canJoin = await checkRoomAccess(user.id, roomId);

      if (!canJoin) {
        socket.emit('error', { message: 'Access denied' });
        return;
      }

      socket.join(`room:${roomId}`);

      logger.info('User joined room', { userId: user.id, roomId });
    });

    // Handle messages
    socket.on('message:send', async ({ content, roomId }) => {
      try {
        // Save message to database
        const message = await messageService.createMessage({
          userId: user.id,
          roomId,
          content,
        });

        // Broadcast to room
        io.to(`room:${roomId}`).emit('message:new', { message });
      } catch (error) {
        logger.error('Failed to send message', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle typing indicators
    socket.on('typing:start', ({ roomId }) => {
      socket.to(`room:${roomId}`).emit('user:typing', {
        userId: user.id,
        isTyping: true,
      });
    });

    socket.on('typing:stop', ({ roomId }) => {
      socket.to(`room:${roomId}`).emit('user:typing', {
        userId: user.id,
        isTyping: false,
      });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info('User disconnected', { userId: user.id, socketId: socket.id });
    });
  });
}

// Emit notifications to specific users
export function sendNotificationToUser(userId: string, notification: Notification) {
  io.to(`user:${userId}`).emit('notification', {
    type: notification.type,
    message: notification.message,
  });
}

// Broadcast to all connected clients
export function broadcastSystemMessage(message: string) {
  io.emit('notification', {
    type: 'system',
    message,
  });
}
```

---

## 5. Application Bootstrap Pattern

### Dependency Container Setup

```typescript
// src/container.ts
import { Pool } from 'pg';
import { createContainer, asClass, asValue } from 'awilix';

import { UserController } from './controllers/user.controller';
import { UserService } from './services/user.service';
import { UserRepository } from './repositories/user.repository';
import { EmailService } from './services/email.service';
import { logger } from './utils/logger';

export function createAppContainer() {
  const container = createContainer();

  // Register database
  const db = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    max: 20,
    idleTimeoutMillis: 30000,
  });

  container.register({
    // Infrastructure
    db: asValue(db),
    logger: asValue(logger),

    // Repositories
    userRepository: asClass(UserRepository).singleton(),

    // Services
    emailService: asClass(EmailService).singleton(),
    userService: asClass(UserService).singleton(),

    // Controllers
    userController: asClass(UserController).scoped(),
  });

  return container;
}

// Usage in routes
export function setupRoutes(app: Express, container: AwilixContainer) {
  const userController = container.resolve<UserController>('userController');

  app.post('/users', (req, res, next) => {
    userController.createUser(req, res, next);
  });
}
```

### Application Startup

```typescript
// src/server.ts
import { app, httpServer } from './app';
import { createAppContainer } from './container';
import { startWorkers } from './workers';
import { logger } from './utils/logger';

async function bootstrap() {
  try {
    // Create DI container
    const container = createAppContainer();

    // Test database connection
    const db = container.resolve('db');
    await db.query('SELECT NOW()');
    logger.info('Database connected');

    // Setup routes with container
    setupRoutes(app, container);

    // Start background workers
    startWorkers();

    // Start server
    const PORT = process.env.PORT || 3000;
    httpServer.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received, shutting down gracefully');

      httpServer.close(() => {
        logger.info('HTTP server closed');
      });

      await db.end();
      logger.info('Database connections closed');

      process.exit(0);
    });
  } catch (error) {
    logger.error('Failed to start application', error);
    process.exit(1);
  }
}

bootstrap();
```

---

## References

- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [Bull Queue Documentation](https://github.com/OptimalBits/bull)
- [Socket.io Documentation](https://socket.io/docs/v4/)
- [Clean Architecture in Node.js](https://www.linkedin.com/pulse/clean-architecture-nodejs-typescript-awohletz/)
