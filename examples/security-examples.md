# Security Examples - Good vs Bad Patterns

## 1. SQL Injection Prevention

### ❌ Bad - Vulnerable to SQL Injection
```typescript
import { Request, Response } from 'express';
import { pool } from './database';

// NEVER DO THIS - String concatenation with user input
async function getUserByUsername(req: Request, res: Response) {
  const { username } = req.query;

  const query = `SELECT * FROM users WHERE username = '${username}'`;
  const result = await pool.query(query);

  res.json(result.rows);
}

// Attack vector: ?username=' OR '1'='1
// This would return all users!
```

### ✅ Good - Parameterized Query
```typescript
import { Request, Response } from 'express';
import { pool } from './database';

async function getUserByUsername(req: Request, res: Response) {
  const { username } = req.query;

  // Use parameterized query
  const query = 'SELECT * FROM users WHERE username = $1';
  const result = await pool.query(query, [username]);

  res.json(result.rows);
}
```

### ✅ Good - ORM with Query Builder
```typescript
import { Request, Response } from 'express';
import { User } from './models/user.model';

async function getUserByUsername(req: Request, res: Response) {
  const { username } = req.query;

  // ORM handles parameterization automatically
  const user = await User.findOne({ where: { username } });

  res.json(user);
}
```

---

## 2. NoSQL Injection Prevention

### ❌ Bad - Vulnerable to NoSQL Injection (MongoDB)
```typescript
import { Request, Response } from 'express';
import { User } from './models/user.model';

// NEVER DO THIS
async function loginUser(req: Request, res: Response) {
  const { username, password } = req.body;

  // Vulnerable: user can pass { $ne: null } as password
  const user = await User.findOne({
    username,
    password, // If password = { $ne: null }, this matches any user!
  });

  if (user) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
}

// Attack payload:
// { "username": "admin", "password": { "$ne": null } }
```

### ✅ Good - Input Validation
```typescript
import { Request, Response } from 'express';
import { User } from './models/user.model';
import bcrypt from 'bcrypt';
import { z } from 'zod';

const loginSchema = z.object({
  username: z.string().min(3).max(30),
  password: z.string().min(8),
});

async function loginUser(req: Request, res: Response) {
  // Validate input types
  const { username, password } = loginSchema.parse(req.body);

  // Fetch user
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Compare hashed password
  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ success: true, token: generateToken(user) });
}
```

---

## 3. Insecure Direct Object Reference (IDOR)

### ❌ Bad - No Authorization Check
```typescript
import { Request, Response } from 'express';
import { Order } from './models/order.model';

// NEVER DO THIS - Any user can access any order
async function getOrder(req: Request, res: Response) {
  const { orderId } = req.params;

  const order = await Order.findById(orderId);

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json(order);
}

// Attack: User can access other users' orders by guessing/incrementing IDs
```

### ✅ Good - Verify Ownership
```typescript
import { Request, Response } from 'express';
import { Order } from './models/order.model';

async function getOrder(req: Request, res: Response) {
  const { orderId } = req.params;
  const userId = req.user!.id; // From authentication middleware

  // Verify ownership
  const order = await Order.findOne({
    _id: orderId,
    userId: userId, // Ensure user owns this order
  });

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json(order);
}
```

### ✅ Better - Use UUIDs Instead of Sequential IDs
```typescript
import { v4 as uuidv4 } from 'uuid';

// In your model
interface Order {
  id: string; // UUID instead of auto-incrementing number
  userId: string;
  // ... other fields
}

// When creating order
const order = await Order.create({
  id: uuidv4(), // Generates unpredictable ID
  userId: req.user.id,
  // ...
});
```

---

## 4. XSS (Cross-Site Scripting) Prevention

### ❌ Bad - No Input Sanitization
```typescript
import { Request, Response } from 'express';

// NEVER render user input directly
async function getUserProfile(req: Request, res: Response) {
  const { username } = req.params;
  const user = await User.findOne({ username });

  // If user.bio contains "<script>alert('XSS')</script>", it will execute
  res.send(`
    <html>
      <body>
        <h1>${user.username}</h1>
        <p>${user.bio}</p>
      </body>
    </html>
  `);
}
```

### ✅ Good - API-First Approach (Return JSON)
```typescript
import { Request, Response } from 'express';

// Return JSON and let frontend handle rendering with proper escaping
async function getUserProfile(req: Request, res: Response) {
  const { username } = req.params;
  const user = await User.findOne({ username });

  res.json({
    username: user.username,
    bio: user.bio, // Frontend framework (React, Vue) will escape this
  });
}
```

### ✅ Good - Sanitize if HTML Rendering Required
```typescript
import { Request, Response } from 'express';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window as any);

async function getUserProfile(req: Request, res: Response) {
  const { username } = req.params;
  const user = await User.findOne({ username });

  // Sanitize HTML content
  const safeBio = DOMPurify.sanitize(user.bio);

  res.send(`
    <html>
      <body>
        <h1>${user.username}</h1>
        <p>${safeBio}</p>
      </body>
    </html>
  `);
}
```

---

## 5. Authentication & JWT Security

### ❌ Bad - Weak JWT Implementation
```typescript
import jwt from 'jsonwebtoken';

// NEVER DO THIS
function generateToken(user: any) {
  // No expiration
  // Weak secret
  // Too much data in token
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      password: user.password, // NEVER include password!
      ssn: user.ssn, // NEVER include sensitive data!
    },
    'secret123' // Weak secret
  );
  // Missing: expiresIn, issuer, audience
}
```

### ✅ Good - Secure JWT Implementation
```typescript
import jwt from 'jsonwebtoken';

interface TokenPayload {
  userId: string;
  role: string;
}

function generateToken(user: any): string {
  const payload: TokenPayload = {
    userId: user.id,
    role: user.role, // Only necessary data
  };

  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: '15m', // Short expiration
    issuer: 'myapp',
    audience: 'myapp-users',
    algorithm: 'HS256',
  });
}

function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    issuer: 'myapp',
    audience: 'myapp-users',
    algorithms: ['HS256'],
  }) as TokenPayload;
}

// Refresh token with longer expiration
function generateRefreshToken(user: any): string {
  return jwt.sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: '7d',
    }
  );
}
```

---

## 6. Password Storage

### ❌ Bad - Plain Text or Weak Hashing
```typescript
import crypto from 'crypto';

// NEVER DO THESE
async function createUser(username: string, password: string) {
  // Option 1: Plain text - NEVER!
  await User.create({ username, password });

  // Option 2: MD5 - NEVER! (fast = easy to crack)
  const hash = crypto.createHash('md5').update(password).digest('hex');
  await User.create({ username, password: hash });

  // Option 3: SHA256 without salt - NEVER!
  const hash2 = crypto.createHash('sha256').update(password).digest('hex');
  await User.create({ username, password: hash2 });
}
```

### ✅ Good - bcrypt with Proper Rounds
```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12; // Adjust based on server capacity

async function createUser(username: string, password: string) {
  // bcrypt automatically handles salting
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  await User.create({
    username,
    password: hashedPassword,
  });
}

async function verifyPassword(
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> {
  return bcrypt.compare(plainPassword, hashedPassword);
}
```

### ✅ Better - argon2 (Winner of Password Hashing Competition)
```typescript
import argon2 from 'argon2';

async function createUser(username: string, password: string) {
  const hashedPassword = await argon2.hash(password, {
    type: argon2.argon2id, // Hybrid of argon2i and argon2d
    memoryCost: 2 ** 16, // 64 MB
    timeCost: 3,
    parallelism: 1,
  });

  await User.create({
    username,
    password: hashedPassword,
  });
}

async function verifyPassword(
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> {
  return argon2.verify(hashedPassword, plainPassword);
}
```

---

## 7. Rate Limiting

### ❌ Bad - No Rate Limiting
```typescript
import { Request, Response } from 'express';

// Vulnerable to brute force attacks
async function login(req: Request, res: Response) {
  const { username, password } = req.body;
  // ... authentication logic
}
```

### ✅ Good - Express Rate Limiting
```typescript
import { rateLimit } from 'express-rate-limit';

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.',
});

// Strict rate limit for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 login attempts per 15 minutes
  skipSuccessfulRequests: true, // Don't count successful requests
});

// Apply to routes
app.use('/api/', apiLimiter);
app.post('/api/auth/login', authLimiter, loginHandler);
```

### ✅ Better - Redis-Based Rate Limiting (Distributed)
```typescript
import { rateLimit } from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

const limiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:',
  }),
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);
```

---

## 8. Command Injection

### ❌ Bad - Unsafe Shell Execution
```typescript
import { exec } from 'child_process';
import { Request, Response } from 'express';

// NEVER DO THIS
async function convertFile(req: Request, res: Response) {
  const { filename } = req.body;

  // Vulnerable to command injection
  exec(`convert ${filename} output.png`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Conversion failed' });
    }
    res.json({ success: true });
  });
}

// Attack: filename = "file.jpg; rm -rf /"
```

### ✅ Good - Use spawn with Array Arguments
```typescript
import { spawn } from 'child_process';
import { Request, Response } from 'express';
import path from 'path';

async function convertFile(req: Request, res: Response) {
  const { filename } = req.body;

  // Validate filename
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  const filepath = path.join('/safe/upload/dir', filename);

  // Use spawn with array args (no shell interpretation)
  const process = spawn('convert', [filepath, 'output.png']);

  process.on('close', (code) => {
    if (code === 0) {
      res.json({ success: true });
    } else {
      res.status(500).json({ error: 'Conversion failed' });
    }
  });
}
```

---

## 9. Secure Session Management

### ❌ Bad - Insecure Session Configuration
```typescript
import session from 'express-session';

// NEVER DO THIS
app.use(
  session({
    secret: 'keyboard cat', // Weak secret
    resave: true,
    saveUninitialized: true,
    cookie: {
      secure: false, // No HTTPS requirement
      httpOnly: false, // Accessible via JavaScript
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year - too long!
    },
  })
);
```

### ✅ Good - Secure Session Configuration
```typescript
import session from 'express-session';
import RedisStore from 'connect-redis';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

app.use(
  session({
    store: new RedisStore({ client: redis }),
    secret: process.env.SESSION_SECRET!,
    name: 'sessionId', // Don't use default 'connect.sid'
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      httpOnly: true, // Not accessible via JavaScript
      maxAge: 3600000, // 1 hour
      sameSite: 'strict', // CSRF protection
      domain: process.env.COOKIE_DOMAIN,
    },
  })
);
```

---

## 10. Environment Variables & Secrets

### ❌ Bad - Hardcoded Secrets
```typescript
// NEVER DO THIS
const JWT_SECRET = 'my-super-secret-key-123';
const DB_PASSWORD = 'password123';
const API_KEY = 'sk_live_abc123xyz';

// Hardcoded in code
const mongoUri = 'mongodb://admin:password123@localhost:27017/mydb';
```

### ✅ Good - Environment Variables
```typescript
// .env file (NEVER commit to git - add to .gitignore)
/*
JWT_SECRET=randomly-generated-secure-secret-here
JWT_REFRESH_SECRET=another-random-secret
DB_HOST=localhost
DB_PORT=27017
DB_NAME=mydb
DB_USER=admin
DB_PASSWORD=secure-password-here
STRIPE_API_KEY=sk_live_...
*/

// config/env.ts
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.string().transform(Number),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  DB_HOST: z.string(),
  DB_PORT: z.string().transform(Number),
  DB_NAME: z.string(),
  DB_USER: z.string(),
  DB_PASSWORD: z.string(),
  STRIPE_API_KEY: z.string().startsWith('sk_'),
});

export const env = envSchema.parse(process.env);

// Usage
const mongoUri = `mongodb://${env.DB_USER}:${env.DB_PASSWORD}@${env.DB_HOST}:${env.DB_PORT}/${env.DB_NAME}`;
```

### ✅ Better - Use Secrets Manager (Production)
```typescript
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const client = new SecretsManagerClient({ region: 'us-east-1' });

async function getSecret(secretName: string): Promise<any> {
  const command = new GetSecretValueCommand({ SecretId: secretName });
  const response = await client.send(command);
  return JSON.parse(response.SecretString!);
}

// Usage
const secrets = await getSecret('prod/myapp/database');
const mongoUri = secrets.MONGODB_URI;
```

---

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
