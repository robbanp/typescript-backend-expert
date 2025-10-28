# Express.js Best Practices for TypeScript Backend

## Project Structure

### Recommended Folder Structure
```
src/
├── config/           # Configuration files
│   ├── database.ts
│   ├── redis.ts
│   └── env.ts
├── controllers/      # Route controllers
│   ├── user.controller.ts
│   └── order.controller.ts
├── middleware/       # Custom middleware
│   ├── auth.ts
│   ├── validation.ts
│   └── error.ts
├── models/          # Data models (Mongoose, Prisma, etc.)
│   ├── user.model.ts
│   └── order.model.ts
├── routes/          # Route definitions
│   ├── user.routes.ts
│   ├── order.routes.ts
│   └── index.ts
├── services/        # Business logic
│   ├── user.service.ts
│   └── order.service.ts
├── types/           # TypeScript types and interfaces
│   ├── express.d.ts
│   └── models.ts
├── utils/           # Utility functions
│   ├── logger.ts
│   └── validators.ts
├── app.ts           # Express app setup
└── server.ts        # Server entry point
```

---

## TypeScript Setup for Express

### Type Definitions
```bash
npm install --save-dev @types/express @types/node
```

### Express Type Extensions
```typescript
// src/types/express.d.ts
import { IUser } from '../models/user.model';

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
      requestId: string;
      startTime: number;
    }

    interface Response {
      // Custom response methods if needed
    }
  }
}

export {};
```

---

## Application Setup

### App Configuration (app.ts)
```typescript
import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import routes from './routes';
import { errorHandler } from './middleware/error';
import { requestLogger } from './middleware/logger';
import { notFoundHandler } from './middleware/notFound';

export function createApp(): Application {
  const app = express();

  // Trust proxy (for load balancers)
  app.set('trust proxy', 1);

  // Security middleware (should be first)
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }));

  // CORS configuration
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    maxAge: 86400, // 24 hours
  }));

  // Rate limiting
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.',
  });
  app.use('/api/', limiter);

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Compression
  app.use(compression());

  // Request logging
  app.use(requestLogger);

  // Health check endpoint (before authentication)
  app.get('/health', (req: Request, res: Response) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  });

  // API routes
  app.use('/api', routes);

  // 404 handler
  app.use(notFoundHandler);

  // Error handling middleware (must be last)
  app.use(errorHandler);

  return app;
}
```

### Server Entry Point (server.ts)
```typescript
import { createApp } from './app';
import { connectDatabase } from './config/database';
import { logger } from './utils/logger';

const PORT = process.env.PORT || 3000;

async function startServer(): Promise<void> {
  try {
    // Connect to database
    await connectDatabase();
    logger.info('Database connected successfully');

    // Create Express app
    const app = createApp();

    // Start server
    const server = app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info(`${signal} received, shutting down gracefully`);

      server.close(async () => {
        logger.info('HTTP server closed');

        // Close database connection
        await disconnectDatabase();
        logger.info('Database connection closed');

        process.exit(0);
      });

      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason: any) => {
  logger.error('Unhandled Rejection', { reason });
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', { error });
  process.exit(1);
});

startServer();
```

---

## Routing Best Practices

### Route Organization (routes/index.ts)
```typescript
import { Router } from 'express';
import userRoutes from './user.routes';
import orderRoutes from './order.routes';
import authRoutes from './auth.routes';

const router = Router();

// Version prefix
router.use('/v1/auth', authRoutes);
router.use('/v1/users', userRoutes);
router.use('/v1/orders', orderRoutes);

export default router;
```

### Individual Route File (routes/user.routes.ts)
```typescript
import { Router } from 'express';
import { authenticate } from '../middleware/auth';
import { authorize } from '../middleware/authorize';
import { validateBody } from '../middleware/validation';
import * as userController from '../controllers/user.controller';
import { CreateUserSchema, UpdateUserSchema } from '../schemas/user.schema';

const router = Router();

// Public routes
router.post(
  '/register',
  validateBody(CreateUserSchema),
  userController.register
);

// Protected routes
router.use(authenticate); // All routes below require authentication

router.get('/me', userController.getCurrentUser);
router.patch(
  '/me',
  validateBody(UpdateUserSchema),
  userController.updateCurrentUser
);

// Admin-only routes
router.get(
  '/',
  authorize('admin'),
  userController.getAllUsers
);

router.get(
  '/:id',
  authorize('admin'),
  userController.getUserById
);

router.delete(
  '/:id',
  authorize('admin'),
  userController.deleteUser
);

export default router;
```

---

## Controllers

### Controller Pattern (controllers/user.controller.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/user.service';
import { CreateUserInput, UpdateUserInput } from '../types/user.types';
import { NotFoundError, ValidationError } from '../utils/errors';

const userService = new UserService();

export async function register(
  req: Request<{}, {}, CreateUserInput>,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const user = await userService.createUser(req.body);

    res.status(201).json({
      status: 'success',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function getCurrentUser(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.user) {
      throw new ValidationError('User not authenticated');
    }

    const user = await userService.getUserById(req.user.id);

    if (!user) {
      throw new NotFoundError('User', req.user.id);
    }

    res.json({
      status: 'success',
      data: { user },
    });
  } catch (error) {
    next(error);
  }
}

export async function getAllUsers(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { page = 1, limit = 20 } = req.query;

    const result = await userService.getUsers({
      page: Number(page),
      limit: Number(limit),
    });

    res.json({
      status: 'success',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function getUserById(
  req: Request<{ id: string }>,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const user = await userService.getUserById(req.params.id);

    if (!user) {
      throw new NotFoundError('User', req.params.id);
    }

    res.json({
      status: 'success',
      data: { user },
    });
  } catch (error) {
    next(error);
  }
}
```

---

## Middleware Best Practices

### Authentication Middleware (middleware/auth.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UnauthorizedError } from '../utils/errors';
import { User } from '../models/user.model';

interface JWTPayload {
  userId: string;
  role: string;
}

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('No token provided');
    }

    const token = authHeader.split(' ')[1];

    // Verify token
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as JWTPayload;

    // Fetch user from database
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      next(new UnauthorizedError('Invalid token'));
    } else {
      next(error);
    }
  }
}
```

### Authorization Middleware (middleware/authorize.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import { ForbiddenError } from '../utils/errors';

export function authorize(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw new ForbiddenError('User not authenticated');
    }

    if (!allowedRoles.includes(req.user.role)) {
      throw new ForbiddenError('Insufficient permissions');
    }

    next();
  };
}
```

### Validation Middleware (middleware/validation.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import { z, ZodSchema } from 'zod';
import { ValidationError } from '../utils/errors';

export function validateBody<T extends ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ValidationError('Validation failed', error.errors));
      } else {
        next(error);
      }
    }
  };
}

export function validateQuery<T extends ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.query = schema.parse(req.query) as any;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ValidationError('Query validation failed', error.errors));
      } else {
        next(error);
      }
    }
  };
}
```

### Request ID Middleware (middleware/requestId.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export function requestId(req: Request, res: Response, next: NextFunction): void {
  req.requestId = req.headers['x-request-id'] as string || uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
}
```

---

## Error Handling

### Error Handler Middleware (middleware/error.ts)
```typescript
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/errors';
import { logger } from '../utils/logger';
import { ZodError } from 'zod';

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Log error
  logger.error('Error occurred', {
    error: err.message,
    stack: err.stack,
    requestId: req.requestId,
    path: req.path,
    method: req.method,
  });

  // Handle Zod validation errors
  if (err instanceof ZodError) {
    res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: err.errors,
    });
    return;
  }

  // Handle known application errors
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      ...(err.details && { details: err.details }),
    });
    return;
  }

  // Handle unexpected errors
  res.status(500).json({
    status: 'error',
    message: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
}

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    status: 'error',
    message: `Route ${req.method} ${req.path} not found`,
  });
}
```

### Async Error Wrapper
```typescript
import { Request, Response, NextFunction, RequestHandler } from 'express';

// Wrapper to catch async errors
export function asyncHandler(fn: RequestHandler): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Usage
router.get('/users', asyncHandler(async (req, res) => {
  const users = await User.find();
  res.json(users);
}));
```

---

## Testing Express Applications

### Setup Tests (tests/setup.ts)
```typescript
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';

let mongoServer: MongoMemoryServer;

export async function setupTestDatabase(): Promise<void> {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
}

export async function teardownTestDatabase(): Promise<void> {
  await mongoose.disconnect();
  await mongoServer.stop();
}

export async function clearDatabase(): Promise<void> {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
}
```

### Integration Tests (tests/user.test.ts)
```typescript
import request from 'supertest';
import { createApp } from '../src/app';
import { setupTestDatabase, teardownTestDatabase, clearDatabase } from './setup';

describe('User API', () => {
  const app = createApp();

  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  afterEach(async () => {
    await clearDatabase();
  });

  describe('POST /api/v1/users/register', () => {
    it('should register a new user', async () => {
      const response = await request(app)
        .post('/api/v1/users/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
        })
        .expect(201);

      expect(response.body.status).toBe('success');
      expect(response.body.data.user.username).toBe('testuser');
      expect(response.body.data.user.password).toBeUndefined();
    });

    it('should return 400 for invalid email', async () => {
      const response = await request(app)
        .post('/api/v1/users/register')
        .send({
          username: 'testuser',
          email: 'invalid-email',
          password: 'Password123!',
        })
        .expect(400);

      expect(response.body.status).toBe('error');
    });
  });

  describe('GET /api/v1/users/me', () => {
    it('should return 401 without token', async () => {
      await request(app)
        .get('/api/v1/users/me')
        .expect(401);
    });

    it('should return current user with valid token', async () => {
      // Create user and get token
      const { token } = await createTestUser();

      const response = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body.data.user).toBeDefined();
    });
  });
});
```

---

## Performance Optimization

### Caching Middleware
```typescript
import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export function cacheMiddleware(ttl: number = 60) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (req.method !== 'GET') {
      return next();
    }

    const key = `cache:${req.originalUrl}`;

    try {
      const cached = await redis.get(key);

      if (cached) {
        res.json(JSON.parse(cached));
        return;
      }

      // Override res.json to cache response
      const originalJson = res.json.bind(res);
      res.json = function(data: any): Response {
        redis.setex(key, ttl, JSON.stringify(data));
        return originalJson(data);
      };

      next();
    } catch (error) {
      // If Redis fails, continue without caching
      next();
    }
  };
}
```

---

## Security Best Practices Checklist

- [ ] Use helmet for security headers
- [ ] Implement rate limiting
- [ ] Validate all inputs with Zod or similar
- [ ] Use parameterized queries (prevent SQL injection)
- [ ] Hash passwords with bcrypt
- [ ] Use HTTPS in production
- [ ] Set secure cookie options
- [ ] Implement CSRF protection for session-based auth
- [ ] Sanitize user input
- [ ] Keep dependencies updated
- [ ] Use environment variables for secrets
- [ ] Implement proper error handling (no sensitive data in errors)
- [ ] Add request timeouts
- [ ] Log security events

---

## References

- [Express.js Official Documentation](https://expressjs.com/)
- [Express Best Practices](https://expressjs.com/en/advanced/best-practice-performance.html)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
