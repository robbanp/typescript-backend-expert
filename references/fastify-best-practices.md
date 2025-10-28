# Fastify Best Practices for TypeScript Backend

## Why Fastify?

Fastify is a high-performance Node.js web framework with the following advantages:
- **Fast**: Up to 2x faster than Express
- **Schema-based**: Built-in JSON schema validation and serialization
- **TypeScript**: First-class TypeScript support
- **Plugin Architecture**: Encapsulated plugin system
- **Developer-friendly**: Extensive plugin ecosystem

---

## Project Structure

### Recommended Folder Structure
```
src/
├── config/              # Configuration files
│   ├── database.ts
│   ├── env.ts
│   └── swagger.ts
├── plugins/             # Fastify plugins
│   ├── auth.ts
│   ├── database.ts
│   ├── redis.ts
│   └── sensible.ts
├── routes/              # Route modules
│   ├── users/
│   │   ├── index.ts
│   │   ├── schema.ts
│   │   └── handler.ts
│   └── orders/
│       ├── index.ts
│       ├── schema.ts
│       └── handler.ts
├── services/            # Business logic
│   ├── user.service.ts
│   └── order.service.ts
├── models/              # Data models
│   ├── user.model.ts
│   └── order.model.ts
├── types/               # TypeScript types
│   ├── fastify.d.ts
│   └── models.ts
├── utils/               # Utilities
│   ├── errors.ts
│   └── logger.ts
├── app.ts               # Fastify app setup
└── server.ts            # Server entry point
```

---

## TypeScript Setup for Fastify

### Installation
```bash
npm install fastify
npm install --save-dev @types/node

# Optional but recommended plugins
npm install @fastify/helmet @fastify/cors @fastify/rate-limit
npm install @fastify/jwt @fastify/cookie @fastify/swagger
```

### Type Augmentation (types/fastify.d.ts)
```typescript
import 'fastify';
import { IUser } from '../models/user.model';

declare module 'fastify' {
  interface FastifyRequest {
    user?: IUser;
  }

  interface FastifyInstance {
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply
    ) => Promise<void>;
  }
}
```

---

## Application Setup

### App Configuration (app.ts)
```typescript
import Fastify, { FastifyInstance, FastifyServerOptions } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

// Plugins
import databasePlugin from './plugins/database';
import authPlugin from './plugins/auth';

// Routes
import userRoutes from './routes/users';
import orderRoutes from './routes/orders';

export async function buildApp(
  opts: FastifyServerOptions = {}
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
      transport:
        process.env.NODE_ENV === 'development'
          ? {
              target: 'pino-pretty',
              options: {
                translateTime: 'HH:MM:ss Z',
                ignore: 'pid,hostname',
              },
            }
          : undefined,
    },
    trustProxy: true,
    requestIdLogLabel: 'reqId',
    disableRequestLogging: false,
    ...opts,
  });

  // Security plugins (register early)
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
      },
    },
  });

  await app.register(cors, {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  });

  // Rate limiting
  await app.register(rateLimit, {
    max: 100,
    timeWindow: '15 minutes',
    ban: 5, // Ban after 5 violations
    cache: 10000, // Cache size
  });

  // Swagger documentation
  if (process.env.NODE_ENV !== 'production') {
    await app.register(swagger, {
      openapi: {
        info: {
          title: 'API Documentation',
          version: '1.0.0',
        },
        servers: [{ url: 'http://localhost:3000' }],
      },
    });

    await app.register(swaggerUi, {
      routePrefix: '/documentation',
    });
  }

  // Custom plugins
  await app.register(databasePlugin);
  await app.register(authPlugin);

  // Health check
  app.get('/health', async (request, reply) => {
    return { status: 'healthy', timestamp: new Date().toISOString() };
  });

  // Routes
  await app.register(userRoutes, { prefix: '/api/v1/users' });
  await app.register(orderRoutes, { prefix: '/api/v1/orders' });

  // Global error handler
  app.setErrorHandler((error, request, reply) => {
    request.log.error(error);

    // Handle validation errors
    if (error.validation) {
      return reply.status(400).send({
        status: 'error',
        message: 'Validation failed',
        errors: error.validation,
      });
    }

    // Custom app errors
    if (error.statusCode) {
      return reply.status(error.statusCode).send({
        status: 'error',
        message: error.message,
      });
    }

    // Unexpected errors
    reply.status(500).send({
      status: 'error',
      message:
        process.env.NODE_ENV === 'production'
          ? 'Internal server error'
          : error.message,
    });
  });

  // 404 handler
  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      status: 'error',
      message: `Route ${request.method} ${request.url} not found`,
    });
  });

  return app;
}
```

### Server Entry Point (server.ts)
```typescript
import { buildApp } from './app';
import { logger } from './utils/logger';

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

async function start(): Promise<void> {
  try {
    const app = await buildApp();

    await app.listen({ port: PORT, host: HOST });

    logger.info(`Server listening on ${HOST}:${PORT}`);

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info(`${signal} received, shutting down gracefully`);

      await app.close();
      logger.info('Server closed');

      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection', { reason });
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error });
  process.exit(1);
});

start();
```

---

## Schema-Based Validation

### Route with Schema (routes/users/schema.ts)
```typescript
import { FastifySchema } from 'fastify';

// Create user schema
export const createUserSchema: FastifySchema = {
  description: 'Create a new user',
  tags: ['users'],
  body: {
    type: 'object',
    required: ['username', 'email', 'password'],
    properties: {
      username: {
        type: 'string',
        minLength: 3,
        maxLength: 30,
      },
      email: {
        type: 'string',
        format: 'email',
      },
      password: {
        type: 'string',
        minLength: 8,
      },
      role: {
        type: 'string',
        enum: ['user', 'admin'],
        default: 'user',
      },
    },
  },
  response: {
    201: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        data: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            username: { type: 'string' },
            email: { type: 'string' },
            role: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
    400: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        message: { type: 'string' },
      },
    },
  },
};

// Get user schema
export const getUserSchema: FastifySchema = {
  description: 'Get user by ID',
  tags: ['users'],
  params: {
    type: 'object',
    required: ['id'],
    properties: {
      id: {
        type: 'string',
        description: 'User ID',
      },
    },
  },
  response: {
    200: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        data: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            username: { type: 'string' },
            email: { type: 'string' },
            role: { type: 'string' },
          },
        },
      },
    },
    404: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        message: { type: 'string' },
      },
    },
  },
};

// List users schema with pagination
export const listUsersSchema: FastifySchema = {
  description: 'List all users with pagination',
  tags: ['users'],
  querystring: {
    type: 'object',
    properties: {
      page: {
        type: 'integer',
        minimum: 1,
        default: 1,
      },
      limit: {
        type: 'integer',
        minimum: 1,
        maximum: 100,
        default: 20,
      },
      role: {
        type: 'string',
        enum: ['user', 'admin'],
      },
    },
  },
  response: {
    200: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        data: {
          type: 'object',
          properties: {
            users: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  username: { type: 'string' },
                  email: { type: 'string' },
                  role: { type: 'string' },
                },
              },
            },
            pagination: {
              type: 'object',
              properties: {
                page: { type: 'integer' },
                limit: { type: 'integer' },
                total: { type: 'integer' },
                hasMore: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  },
};
```

### TypeScript Types from Schema
```typescript
import { FromSchema } from 'json-schema-to-ts';

const createUserBodySchema = {
  type: 'object',
  required: ['username', 'email', 'password'],
  properties: {
    username: { type: 'string' },
    email: { type: 'string' },
    password: { type: 'string' },
    role: { type: 'string', enum: ['user', 'admin'] },
  },
} as const;

// Automatically infer TypeScript type from JSON schema
export type CreateUserBody = FromSchema<typeof createUserBodySchema>;

// Or use Fastify's TypeProvider
import { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { Type, Static } from '@sinclair/typebox';

const UserSchema = Type.Object({
  id: Type.String(),
  username: Type.String(),
  email: Type.String({ format: 'email' }),
  role: Type.Union([Type.Literal('user'), Type.Literal('admin')]),
});

type User = Static<typeof UserSchema>;
```

---

## Route Handlers

### Route Handler (routes/users/handler.ts)
```typescript
import { FastifyRequest, FastifyReply } from 'fastify';
import { UserService } from '../../services/user.service';

const userService = new UserService();

interface CreateUserBody {
  username: string;
  email: string;
  password: string;
  role?: 'user' | 'admin';
}

interface GetUserParams {
  id: string;
}

interface ListUsersQuery {
  page?: number;
  limit?: number;
  role?: 'user' | 'admin';
}

export async function createUserHandler(
  request: FastifyRequest<{ Body: CreateUserBody }>,
  reply: FastifyReply
): Promise<void> {
  const user = await userService.createUser(request.body);

  reply.status(201).send({
    status: 'success',
    data: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    },
  });
}

export async function getUserHandler(
  request: FastifyRequest<{ Params: GetUserParams }>,
  reply: FastifyReply
): Promise<void> {
  const user = await userService.getUserById(request.params.id);

  if (!user) {
    return reply.status(404).send({
      status: 'error',
      message: 'User not found',
    });
  }

  reply.send({
    status: 'success',
    data: { user },
  });
}

export async function listUsersHandler(
  request: FastifyRequest<{ Querystring: ListUsersQuery }>,
  reply: FastifyReply
): Promise<void> {
  const { page = 1, limit = 20, role } = request.query;

  const result = await userService.getUsers({ page, limit, role });

  reply.send({
    status: 'success',
    data: result,
  });
}

export async function getCurrentUserHandler(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  if (!request.user) {
    return reply.status(401).send({
      status: 'error',
      message: 'Not authenticated',
    });
  }

  reply.send({
    status: 'success',
    data: { user: request.user },
  });
}
```

### Route Registration (routes/users/index.ts)
```typescript
import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import {
  createUserHandler,
  getUserHandler,
  listUsersHandler,
  getCurrentUserHandler,
} from './handler';
import {
  createUserSchema,
  getUserSchema,
  listUsersSchema,
} from './schema';

export default async function userRoutes(
  fastify: FastifyInstance,
  opts: FastifyPluginOptions
): Promise<void> {
  // Public routes
  fastify.post('/', {
    schema: createUserSchema,
    handler: createUserHandler,
  });

  // Protected routes
  fastify.get('/me', {
    onRequest: [fastify.authenticate],
    handler: getCurrentUserHandler,
  });

  // Admin routes
  fastify.get('/', {
    onRequest: [fastify.authenticate],
    schema: listUsersSchema,
    handler: listUsersHandler,
  });

  fastify.get('/:id', {
    onRequest: [fastify.authenticate],
    schema: getUserSchema,
    handler: getUserHandler,
  });
}
```

---

## Plugins

### Authentication Plugin (plugins/auth.ts)
```typescript
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import jwt from '@fastify/jwt';
import { User } from '../models/user.model';

async function authPlugin(fastify: FastifyInstance): Promise<void> {
  // Register JWT plugin
  await fastify.register(jwt, {
    secret: process.env.JWT_SECRET!,
    sign: {
      expiresIn: '15m',
    },
  });

  // Decorate fastify instance with authenticate function
  fastify.decorate(
    'authenticate',
    async function (request: FastifyRequest, reply: FastifyReply) {
      try {
        const decoded = await request.jwtVerify<{ userId: string }>();

        // Fetch user from database
        const user = await User.findById(decoded.userId).select('-password');

        if (!user) {
          return reply.status(401).send({
            status: 'error',
            message: 'User not found',
          });
        }

        request.user = user;
      } catch (error) {
        reply.status(401).send({
          status: 'error',
          message: 'Invalid or expired token',
        });
      }
    }
  );
}

export default fp(authPlugin, {
  name: 'auth',
  dependencies: [],
});
```

### Database Plugin (plugins/database.ts)
```typescript
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import mongoose from 'mongoose';

async function databasePlugin(fastify: FastifyInstance): Promise<void> {
  const mongoUri = process.env.MONGODB_URI!;

  try {
    await mongoose.connect(mongoUri);
    fastify.log.info('Database connected successfully');

    // Close connection on app close
    fastify.addHook('onClose', async () => {
      await mongoose.connection.close();
      fastify.log.info('Database connection closed');
    });
  } catch (error) {
    fastify.log.error('Database connection failed', error);
    throw error;
  }
}

export default fp(databasePlugin, {
  name: 'database',
});
```

---

## Hooks

### Request/Response Hooks
```typescript
import { FastifyInstance } from 'fastify';

export default async function hooksPlugin(
  fastify: FastifyInstance
): Promise<void> {
  // onRequest - runs first
  fastify.addHook('onRequest', async (request, reply) => {
    request.log.info({ url: request.url }, 'Incoming request');
  });

  // preValidation - before validation
  fastify.addHook('preValidation', async (request, reply) => {
    // Custom validation logic
  });

  // preHandler - after validation, before handler
  fastify.addHook('preHandler', async (request, reply) => {
    request.startTime = Date.now();
  });

  // onSend - before response sent
  fastify.addHook('onSend', async (request, reply, payload) => {
    const duration = Date.now() - (request.startTime || 0);
    request.log.info({ duration }, 'Request completed');
    return payload;
  });

  // onResponse - after response sent
  fastify.addHook('onResponse', async (request, reply) => {
    // Cleanup, logging, etc.
  });

  // onError - when error occurs
  fastify.addHook('onError', async (request, reply, error) => {
    request.log.error({ error }, 'Request error');
  });
}
```

---

## Testing Fastify Applications

### Test Setup (tests/helper.ts)
```typescript
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app';
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';

let mongoServer: MongoMemoryServer;

export async function setupTestApp(): Promise<FastifyInstance> {
  // Start in-memory MongoDB
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  process.env.MONGODB_URI = uri;

  // Build app
  const app = await buildApp({ logger: false });

  return app;
}

export async function teardownTestApp(app: FastifyInstance): Promise<void> {
  await app.close();
  await mongoose.connection.close();
  await mongoServer.stop();
}

export async function clearDatabase(): Promise<void> {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
}
```

### Integration Tests (tests/users.test.ts)
```typescript
import { FastifyInstance } from 'fastify';
import { setupTestApp, teardownTestApp, clearDatabase } from './helper';

describe('User Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await setupTestApp();
  });

  afterAll(async () => {
    await teardownTestApp(app);
  });

  afterEach(async () => {
    await clearDatabase();
  });

  describe('POST /api/v1/users', () => {
    it('should create a new user', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/users',
        payload: {
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
        },
      });

      expect(response.statusCode).toBe(201);
      const body = response.json();
      expect(body.status).toBe('success');
      expect(body.data.user.username).toBe('testuser');
    });

    it('should return 400 for invalid email', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/users',
        payload: {
          username: 'testuser',
          email: 'invalid-email',
          password: 'Password123!',
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('GET /api/v1/users/me', () => {
    it('should return 401 without token', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/users/me',
      });

      expect(response.statusCode).toBe(401);
    });

    it('should return current user with valid token', async () => {
      // Create user and generate token
      const token = await createTestUserAndGetToken(app);

      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/users/me',
        headers: {
          authorization: `Bearer ${token}`,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.data.user).toBeDefined();
    });
  });
});
```

---

## Performance Best Practices

### Serialization Performance
```typescript
// Use schema for fast serialization
const userResponseSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    username: { type: 'string' },
    email: { type: 'string' },
    // Fastify will strip any fields not in schema
  },
};

// In route
fastify.get('/users/:id', {
  schema: {
    response: {
      200: userResponseSchema,
    },
  },
  handler: async (request, reply) => {
    const user = await User.findById(request.params.id);
    // Fastify auto-serializes using schema (much faster than JSON.stringify)
    return user;
  },
});
```

### Connection Pooling
```typescript
// MongoDB with connection pooling
await mongoose.connect(mongoUri, {
  maxPoolSize: 10,
  minPoolSize: 5,
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
});
```

---

## Security Checklist

- [ ] Use @fastify/helmet for security headers
- [ ] Implement @fastify/rate-limit
- [ ] Validate all inputs with JSON schemas
- [ ] Use @fastify/jwt for authentication
- [ ] Set secure cookie options with @fastify/cookie
- [ ] Enable CORS properly with @fastify/cors
- [ ] Use HTTPS in production
- [ ] Implement CSRF protection if needed
- [ ] Keep dependencies updated
- [ ] Use environment variables for secrets
- [ ] Set request payload limits
- [ ] Implement proper error handling (no sensitive data)
- [ ] Log security events

---

## References

- [Fastify Official Documentation](https://www.fastify.io/)
- [Fastify TypeScript](https://www.fastify.io/docs/latest/Reference/TypeScript/)
- [Fastify Best Practices](https://www.fastify.io/docs/latest/Guides/Best-Practices/)
- [Fastify Plugins](https://www.fastify.io/ecosystem/)
