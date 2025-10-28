# Performance Checklist for TypeScript Backend Applications

## Database Performance

### Query Optimization
- [ ] Indexes on frequently queried columns
- [ ] Composite indexes for multi-column queries
- [ ] Query execution plans analyzed
- [ ] N+1 query problems resolved
- [ ] Pagination for large datasets
- [ ] Select only needed columns (avoid SELECT *)
- [ ] Batch operations instead of loops

**Example - N+1 Problem:**
```typescript
// ❌ Bad - N+1 queries
async function getOrdersWithUsers() {
  const orders = await Order.find();
  for (const order of orders) {
    order.user = await User.findById(order.userId); // N queries
  }
  return orders;
}

// ✅ Good - Single join query
async function getOrdersWithUsers() {
  return Order.find().populate('user'); // 1 query with join
}

// ✅ Good - DataLoader pattern
import DataLoader from 'dataloader';

const userLoader = new DataLoader(async (userIds: string[]) => {
  const users = await User.find({ _id: { $in: userIds } });
  const userMap = new Map(users.map(u => [u.id, u]));
  return userIds.map(id => userMap.get(id));
});

async function getOrdersWithUsers() {
  const orders = await Order.find();
  await Promise.all(
    orders.map(order =>
      userLoader.load(order.userId).then(user => order.user = user)
    )
  );
  return orders;
}
```

### Connection Pooling
- [ ] Database connection pool configured
- [ ] Pool size optimized for workload
- [ ] Connection timeout set
- [ ] Idle connection timeout
- [ ] Connection retry logic

**Example - PostgreSQL Connection Pool:**
```typescript
import { Pool } from 'pg';

const pool = new Pool({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 20, // Maximum pool size
  min: 5,  // Minimum pool size
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Proper connection handling
async function queryDatabase(query: string, params: any[]) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result.rows;
  } finally {
    client.release(); // Always release
  }
}
```

### Caching Strategy
- [ ] Query result caching where appropriate
- [ ] Cache invalidation strategy
- [ ] Redis or similar for distributed caching
- [ ] TTL configured for cache entries
- [ ] Cache hit/miss monitoring

**Example - Redis Caching:**
```typescript
import Redis from 'ioredis';

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || '6379'),
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: true,
});

async function getCachedUser(userId: string) {
  const cacheKey = `user:${userId}`;

  // Try cache first
  const cached = await redis.get(cacheKey);
  if (cached) {
    return JSON.parse(cached);
  }

  // Cache miss - fetch from database
  const user = await User.findById(userId);

  // Store in cache with 1 hour TTL
  await redis.setex(cacheKey, 3600, JSON.stringify(user));

  return user;
}

// Cache invalidation
async function updateUser(userId: string, updates: any) {
  const user = await User.findByIdAndUpdate(userId, updates);
  await redis.del(`user:${userId}`); // Invalidate cache
  return user;
}
```

---

## Async Operations & Event Loop

### Non-Blocking Operations
- [ ] CPU-intensive tasks offloaded to worker threads
- [ ] No synchronous file operations in request handlers
- [ ] Async/await used correctly
- [ ] Promises handled properly (no floating promises)
- [ ] Event loop monitoring

**Example - Worker Threads for CPU-Intensive Tasks:**
```typescript
import { Worker } from 'worker_threads';

function runCpuIntensiveTask(data: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const worker = new Worker('./cpu-task-worker.js', {
      workerData: data
    });

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}

// Express route using worker
app.post('/api/process', async (req, res) => {
  try {
    const result = await runCpuIntensiveTask(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Processing failed' });
  }
});
```

### Promise Management
- [ ] No unhandled promise rejections
- [ ] Proper error handling in async functions
- [ ] Promise.all() for parallel operations
- [ ] Promise.allSettled() when some failures acceptable
- [ ] Avoid await in loops (use Promise.all)

**Example - Parallel Operations:**
```typescript
// ❌ Bad - Sequential execution
async function getUserData(userId: string) {
  const user = await fetchUser(userId);
  const orders = await fetchOrders(userId);
  const preferences = await fetchPreferences(userId);
  return { user, orders, preferences };
}

// ✅ Good - Parallel execution
async function getUserData(userId: string) {
  const [user, orders, preferences] = await Promise.all([
    fetchUser(userId),
    fetchOrders(userId),
    fetchPreferences(userId)
  ]);
  return { user, orders, preferences };
}
```

---

## HTTP & Network Performance

### Response Optimization
- [ ] Compression enabled (gzip, brotli)
- [ ] Response streaming for large payloads
- [ ] HTTP/2 enabled
- [ ] Keep-Alive connections
- [ ] Proper cache headers (ETag, Last-Modified)
- [ ] Static asset caching

**Example - Compression (Express):**
```typescript
import compression from 'compression';

app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
  level: 6, // Balance between compression and speed
  threshold: 1024, // Only compress responses > 1KB
}));
```

**Example - Streaming Large Responses:**
```typescript
import { createReadStream } from 'fs';
import { pipeline } from 'stream/promises';

// Stream file download
app.get('/api/download/:fileId', async (req, res) => {
  const filePath = await getFilePath(req.params.fileId);

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const fileStream = createReadStream(filePath);
  await pipeline(fileStream, res);
});

// Stream database results
app.get('/api/large-dataset', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.write('[');

  let first = true;
  const cursor = db.collection('items').find().cursor();

  for await (const doc of cursor) {
    if (!first) res.write(',');
    res.write(JSON.stringify(doc));
    first = false;
  }

  res.write(']');
  res.end();
});
```

### Request Size Limits
- [ ] Body parser limits configured
- [ ] File upload size limits
- [ ] Request timeout configured
- [ ] Payload too large handling

**Example - Request Limits (Express):**
```typescript
import express from 'express';

app.use(express.json({
  limit: '10mb',
  strict: true
}));

app.use(express.urlencoded({
  limit: '10mb',
  extended: true
}));

// Request timeout
app.use((req, res, next) => {
  req.setTimeout(30000, () => {
    res.status(408).json({ error: 'Request timeout' });
  });
  next();
});
```

---

## Memory Management

### Memory Leak Prevention
- [ ] Event listeners properly removed
- [ ] Database connections closed
- [ ] File handles closed
- [ ] Timers cleared
- [ ] Large objects released
- [ ] Memory monitoring in production

**Example - Proper Cleanup:**
```typescript
import { EventEmitter } from 'events';

class DataProcessor extends EventEmitter {
  private timer?: NodeJS.Timeout;
  private connections: Connection[] = [];

  start() {
    this.timer = setInterval(() => this.process(), 1000);
  }

  async process() {
    // Process data
  }

  // Proper cleanup
  async stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    // Close all connections
    await Promise.all(
      this.connections.map(conn => conn.close())
    );
    this.connections = [];

    // Remove all listeners
    this.removeAllListeners();
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  await processor.stop();
  await server.close();
  await db.disconnect();
  process.exit(0);
});
```

### Buffer Management
- [ ] Stream large files instead of loading into memory
- [ ] Buffer pooling for network operations
- [ ] Proper buffer cleanup
- [ ] Memory limits for buffers

---

## Caching Strategies

### Application-Level Caching
- [ ] In-memory cache for hot data (LRU cache)
- [ ] Redis for distributed caching
- [ ] Cache warming on startup
- [ ] Cache stampede prevention
- [ ] Cache versioning

**Example - LRU Cache:**
```typescript
import LRU from 'lru-cache';

const cache = new LRU<string, any>({
  max: 500, // Maximum items
  maxAge: 1000 * 60 * 60, // 1 hour TTL
  updateAgeOnGet: true,
});

async function getProductWithCache(productId: string) {
  const cacheKey = `product:${productId}`;

  // Check cache
  if (cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }

  // Cache miss
  const product = await Product.findById(productId);
  cache.set(cacheKey, product);

  return product;
}
```

### HTTP Caching Headers
- [ ] ETag generation and validation
- [ ] Last-Modified headers
- [ ] Cache-Control headers
- [ ] Vary header for content negotiation

**Example - HTTP Caching:**
```typescript
import crypto from 'crypto';

// ETag generation
function generateETag(data: any): string {
  return crypto
    .createHash('md5')
    .update(JSON.stringify(data))
    .digest('hex');
}

app.get('/api/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id);

  const etag = generateETag(product);
  const lastModified = product.updatedAt.toUTCString();

  // Check if client has cached version
  if (req.headers['if-none-match'] === etag) {
    return res.status(304).end();
  }

  res.set({
    'ETag': etag,
    'Last-Modified': lastModified,
    'Cache-Control': 'private, max-age=3600', // 1 hour
  });

  res.json(product);
});
```

---

## Load Balancing & Clustering

### Node.js Clustering
- [ ] PM2 or cluster module for multi-core usage
- [ ] Shared state handled (Redis for sessions)
- [ ] Graceful worker restarts
- [ ] Health checks

**Example - PM2 Ecosystem:**
```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'api',
    script: './dist/server.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster',
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
```

---

## Monitoring & Profiling

### Performance Monitoring
- [ ] Response time tracking
- [ ] Database query timing
- [ ] Memory usage monitoring
- [ ] CPU usage monitoring
- [ ] Event loop lag monitoring
- [ ] Error rate tracking

**Example - Performance Middleware:**
```typescript
import { performance } from 'perf_hooks';

// Request timing middleware
app.use((req, res, next) => {
  const start = performance.now();

  res.on('finish', () => {
    const duration = performance.now() - start;
    logger.info('Request completed', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: Math.round(duration),
      userAgent: req.headers['user-agent'],
    });

    // Alert on slow requests
    if (duration > 1000) {
      logger.warn('Slow request detected', {
        url: req.url,
        duration: Math.round(duration),
      });
    }
  });

  next();
});
```

### Profiling Tools
- [ ] clinic.js for production profiling
- [ ] node --inspect for debugging
- [ ] Autocannon or Artillery for load testing
- [ ] New Relic / DataDog / AppDynamics

---

## Framework-Specific Optimizations

### Express Performance
- [ ] Production mode (`NODE_ENV=production`)
- [ ] View caching enabled
- [ ] Middleware order optimized
- [ ] Static file serving with nginx (production)
- [ ] express.json() with limit

**Example - Express Production Config:**
```typescript
const app = express();

// Set NODE_ENV=production
if (process.env.NODE_ENV === 'production') {
  app.set('view cache', true);
  app.enable('trust proxy'); // Behind load balancer
}

// Optimize middleware order (most specific first)
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
```

### Fastify Performance
- [ ] Schema validation for serialization speed
- [ ] Precompiled routes
- [ ] Custom serializers
- [ ] Logging level optimized
- [ ] Ajv compiled schemas

**Example - Fastify Schema Validation:**
```typescript
const schema = {
  body: {
    type: 'object',
    required: ['username', 'email'],
    properties: {
      username: { type: 'string', minLength: 3, maxLength: 30 },
      email: { type: 'string', format: 'email' }
    }
  },
  response: {
    200: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        username: { type: 'string' },
        email: { type: 'string' }
      }
    }
  }
};

// Schema provides both validation AND fast serialization
fastify.post('/users', { schema }, async (request, reply) => {
  const user = await createUser(request.body);
  return user; // Auto-serialized using schema
});
```

---

## Asset Optimization

### Static Assets
- [ ] CDN for static assets
- [ ] Asset versioning/fingerprinting
- [ ] Minification (CSS, JS)
- [ ] Image optimization
- [ ] Lazy loading where appropriate

---

## API Design Performance

### Pagination
- [ ] Cursor-based pagination for large datasets
- [ ] Limit max page size
- [ ] Total count optional (expensive)

**Example - Cursor Pagination:**
```typescript
interface PaginationParams {
  cursor?: string;
  limit?: number;
}

async function getPaginatedOrders(params: PaginationParams) {
  const limit = Math.min(params.limit || 20, 100); // Max 100

  const query: any = {};
  if (params.cursor) {
    query._id = { $gt: params.cursor };
  }

  const orders = await Order.find(query)
    .limit(limit + 1) // Fetch one extra to check if more exist
    .sort({ _id: 1 });

  const hasMore = orders.length > limit;
  const items = hasMore ? orders.slice(0, -1) : orders;
  const nextCursor = hasMore ? items[items.length - 1]._id : null;

  return {
    items,
    nextCursor,
    hasMore
  };
}
```

### Field Selection
- [ ] Allow clients to request specific fields
- [ ] GraphQL or REST field selection
- [ ] Default to essential fields only

---

## Testing Performance

### Load Testing
- [ ] Baseline performance metrics
- [ ] Load testing with realistic traffic
- [ ] Stress testing to find limits
- [ ] Spike testing for traffic bursts
- [ ] Soak testing for memory leaks

**Example - Autocannon Load Test:**
```bash
# Install autocannon
npm install -g autocannon

# Run load test
autocannon -c 100 -d 30 http://localhost:3000/api/products
```

---

## Performance Budget

### Define Limits
- [ ] Response time SLA (e.g., p95 < 200ms)
- [ ] Maximum memory usage
- [ ] Maximum CPU usage
- [ ] Database query time limits
- [ ] API rate limits

---

## References

- [Node.js Performance Best Practices](https://nodejs.org/en/docs/guides/simple-profiling/)
- [Express Performance Best Practices](https://expressjs.com/en/advanced/best-practice-performance.html)
- [Fastify Benchmarks](https://www.fastify.io/benchmarks/)
- [clinic.js Documentation](https://clinicjs.org/)
