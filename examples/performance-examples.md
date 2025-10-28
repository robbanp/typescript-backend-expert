# Performance Examples - Good vs Bad Patterns

## 1. Database N+1 Query Problem

### ❌ Bad - N+1 Queries
```typescript
import { Request, Response } from 'express';
import { Order, User } from './models';

// Makes 1 query for orders, then N queries for users (one per order)
async function getOrdersWithUsers(req: Request, res: Response) {
  const orders = await Order.find(); // 1 query

  // N additional queries (one per order)
  for (const order of orders) {
    order.user = await User.findById(order.userId); // N queries
  }

  res.json(orders);
}

// Total: 1 + N queries (if 100 orders = 101 queries!)
```

### ✅ Good - Join or Populate
```typescript
import { Request, Response } from 'express';
import { Order } from './models';

// Mongoose populate (single query with join)
async function getOrdersWithUsers(req: Request, res: Response) {
  const orders = await Order.find().populate('user'); // 1-2 queries

  res.json(orders);
}
```

### ✅ Good - DataLoader Pattern
```typescript
import DataLoader from 'dataloader';
import { User } from './models';

// Create a DataLoader instance
const userLoader = new DataLoader(async (userIds: string[]) => {
  // Batches multiple requests into one query
  const users = await User.find({ _id: { $in: userIds } });

  // Return users in same order as requested IDs
  const userMap = new Map(users.map(u => [u.id.toString(), u]));
  return userIds.map(id => userMap.get(id.toString()) || null);
});

async function getOrdersWithUsers(req: Request, res: Response) {
  const orders = await Order.find();

  // Load all users in a single batched query
  await Promise.all(
    orders.map(async order => {
      order.user = await userLoader.load(order.userId);
    })
  );

  res.json(orders);
}
```

---

## 2. Inefficient Array Operations

### ❌ Bad - Sequential Processing
```typescript
async function processOrders(orderIds: string[]) {
  const results = [];

  // Processes one at a time (sequential)
  for (const orderId of orderIds) {
    const order = await Order.findById(orderId);
    const processed = await processOrder(order);
    results.push(processed);
  }

  return results;
}

// If each operation takes 100ms and there are 10 orders:
// Total time = 10 * 100ms = 1000ms
```

### ✅ Good - Parallel Processing
```typescript
async function processOrders(orderIds: string[]) {
  // Process all orders in parallel
  const results = await Promise.all(
    orderIds.map(async orderId => {
      const order = await Order.findById(orderId);
      return processOrder(order);
    })
  );

  return results;
}

// If each operation takes 100ms and there are 10 orders:
// Total time ≈ 100ms (all run in parallel)
```

### ✅ Better - Controlled Concurrency
```typescript
import pLimit from 'p-limit';

async function processOrders(orderIds: string[]) {
  // Limit concurrent operations to avoid overwhelming the system
  const limit = pLimit(5); // Max 5 concurrent operations

  const results = await Promise.all(
    orderIds.map(orderId =>
      limit(async () => {
        const order = await Order.findById(orderId);
        return processOrder(order);
      })
    )
  );

  return results;
}
```

---

## 3. Blocking the Event Loop

### ❌ Bad - CPU-Intensive Synchronous Operation
```typescript
import { Request, Response } from 'express';

// Blocks the event loop, freezes all other requests
function computeIntensive(req: Request, res: Response) {
  let result = 0;

  // Synchronous computation blocks everything
  for (let i = 0; i < 10_000_000_000; i++) {
    result += Math.sqrt(i);
  }

  res.json({ result });
}

// While this runs, the server cannot handle ANY other requests!
```

### ✅ Good - Worker Threads for CPU-Intensive Tasks
```typescript
import { Worker } from 'worker_threads';
import { Request, Response } from 'express';
import path from 'path';

function computeIntensive(req: Request, res: Response) {
  const worker = new Worker(
    path.join(__dirname, 'workers', 'compute-worker.js'),
    {
      workerData: { /* data to process */ }
    }
  );

  worker.on('message', (result) => {
    res.json({ result });
  });

  worker.on('error', (error) => {
    res.status(500).json({ error: 'Computation failed' });
  });

  // Server can handle other requests while worker computes
}
```

```typescript
// workers/compute-worker.js
import { parentPort, workerData } from 'worker_threads';

let result = 0;
for (let i = 0; i < 10_000_000_000; i++) {
  result += Math.sqrt(i);
}

parentPort?.postMessage(result);
```

---

## 4. Memory Leaks

### ❌ Bad - Event Listeners Not Cleaned Up
```typescript
import { EventEmitter } from 'events';

class DataService extends EventEmitter {
  private intervals: NodeJS.Timeout[] = [];

  start() {
    // Creates interval but never cleans up
    const interval = setInterval(() => {
      this.emit('data', this.fetchData());
    }, 1000);

    this.intervals.push(interval);
  }

  // Missing cleanup - memory leak!
}

// Each time a new instance is created, old intervals keep running
```

### ✅ Good - Proper Cleanup
```typescript
import { EventEmitter } from 'events';

class DataService extends EventEmitter {
  private intervals: NodeJS.Timeout[] = [];

  start() {
    const interval = setInterval(() => {
      this.emit('data', this.fetchData());
    }, 1000);

    this.intervals.push(interval);
  }

  stop() {
    // Clear all intervals
    for (const interval of this.intervals) {
      clearInterval(interval);
    }
    this.intervals = [];

    // Remove all listeners
    this.removeAllListeners();
  }

  private fetchData() {
    // Implementation
  }
}

// Proper usage
const service = new DataService();
service.start();

// Later, or on shutdown:
service.stop();
```

### ✅ Good - Graceful Shutdown
```typescript
import express from 'express';
import { Server } from 'http';

const app = express();
let server: Server;

async function startServer() {
  server = app.listen(3000);

  // Setup graceful shutdown
  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
}

async function gracefulShutdown(signal: string) {
  console.log(`${signal} received, shutting down gracefully`);

  // Stop accepting new connections
  server.close(async () => {
    console.log('HTTP server closed');

    // Clean up resources
    await db.disconnect();
    await redis.quit();

    process.exit(0);
  });

  // Force shutdown after timeout
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
}
```

---

## 5. Inefficient Database Queries

### ❌ Bad - Fetching All Records
```typescript
async function getActiveUsers(req: Request, res: Response) {
  // Loads ALL users into memory - very inefficient
  const allUsers = await User.find();

  const activeUsers = allUsers.filter(user => user.isActive);

  res.json(activeUsers);
}
```

### ✅ Good - Filter at Database Level
```typescript
async function getActiveUsers(req: Request, res: Response) {
  // Database filters - much more efficient
  const activeUsers = await User.find({ isActive: true });

  res.json(activeUsers);
}
```

### ✅ Better - Pagination and Projection
```typescript
async function getActiveUsers(req: Request, res: Response) {
  const page = parseInt(req.query.page as string) || 1;
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
  const skip = (page - 1) * limit;

  // Only fetch needed fields, with pagination
  const users = await User.find({ isActive: true })
    .select('id username email createdAt') // Projection - only needed fields
    .skip(skip)
    .limit(limit)
    .lean(); // Convert to plain JavaScript object (faster)

  const total = await User.countDocuments({ isActive: true });

  res.json({
    users,
    pagination: {
      page,
      limit,
      total,
      hasMore: skip + users.length < total,
    },
  });
}
```

---

## 6. Response Compression

### ❌ Bad - No Compression
```typescript
import express from 'express';

const app = express();

// Sending large JSON responses without compression
app.get('/api/products', async (req, res) => {
  const products = await Product.find(); // Large dataset
  res.json(products); // Sends uncompressed
});
```

### ✅ Good - Enable Compression
```typescript
import express from 'express';
import compression from 'compression';

const app = express();

// Enable compression middleware
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

app.get('/api/products', async (req, res) => {
  const products = await Product.find();
  res.json(products); // Automatically compressed
});
```

---

## 7. Caching Strategies

### ❌ Bad - No Caching
```typescript
async function getPopularProducts(req: Request, res: Response) {
  // Runs expensive query on every request
  const products = await Product.find()
    .sort({ views: -1 })
    .limit(10)
    .populate('category')
    .populate('reviews');

  res.json(products);
}
```

### ✅ Good - In-Memory Cache
```typescript
import LRU from 'lru-cache';

const cache = new LRU<string, any>({
  max: 500,
  ttl: 1000 * 60 * 5, // 5 minutes
});

async function getPopularProducts(req: Request, res: Response) {
  const cacheKey = 'popular-products';

  // Check cache first
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  // Cache miss - fetch from database
  const products = await Product.find()
    .sort({ views: -1 })
    .limit(10)
    .populate('category')
    .populate('reviews');

  // Store in cache
  cache.set(cacheKey, products);

  res.json(products);
}
```

### ✅ Better - Redis Cache with Stale-While-Revalidate
```typescript
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

async function getPopularProducts(req: Request, res: Response) {
  const cacheKey = 'popular-products';
  const cacheTTL = 300; // 5 minutes
  const staleTTL = 600; // 10 minutes

  try {
    // Try to get from cache
    const cached = await redis.get(cacheKey);

    if (cached) {
      const data = JSON.parse(cached);

      // Check if stale
      const cacheTime = await redis.ttl(cacheKey);
      if (cacheTime < cacheTTL / 2) {
        // Stale - refresh in background
        refreshCache(cacheKey, cacheTTL);
      }

      return res.json(data);
    }

    // Cache miss
    const products = await fetchPopularProducts();
    await redis.setex(cacheKey, staleTTL, JSON.stringify(products));

    res.json(products);
  } catch (error) {
    // If Redis fails, fall back to database
    const products = await fetchPopularProducts();
    res.json(products);
  }
}

async function fetchPopularProducts() {
  return Product.find()
    .sort({ views: -1 })
    .limit(10)
    .populate('category')
    .populate('reviews');
}

async function refreshCache(key: string, ttl: number) {
  // Refresh cache in background
  setImmediate(async () => {
    try {
      const products = await fetchPopularProducts();
      await redis.setex(key, ttl, JSON.stringify(products));
    } catch (error) {
      console.error('Cache refresh failed', error);
    }
  });
}
```

---

## 8. Database Connection Pooling

### ❌ Bad - No Connection Pool
```typescript
import { MongoClient } from 'mongodb';

// Creates new connection for each request
async function getUser(userId: string) {
  const client = new MongoClient(process.env.MONGODB_URI!);
  await client.connect(); // Expensive operation

  const db = client.db();
  const user = await db.collection('users').findOne({ _id: userId });

  await client.close();

  return user;
}
```

### ✅ Good - Connection Pool
```typescript
import mongoose from 'mongoose';

// Configure connection pool
await mongoose.connect(process.env.MONGODB_URI!, {
  maxPoolSize: 10, // Maximum connections
  minPoolSize: 5, // Minimum connections
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
});

// Reuses connections from pool
async function getUser(userId: string) {
  return User.findById(userId);
}
```

---

## 9. Streaming Large Responses

### ❌ Bad - Loading Everything into Memory
```typescript
import { Request, Response } from 'express';
import fs from 'fs';

// Loads entire file into memory
async function downloadFile(req: Request, res: Response) {
  const filePath = getFilePath(req.params.fileId);

  // Reads entire file - could be gigabytes!
  const fileContent = fs.readFileSync(filePath);

  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(fileContent);
}
```

### ✅ Good - Stream Response
```typescript
import { Request, Response } from 'express';
import { createReadStream } from 'fs';
import { pipeline } from 'stream/promises';

async function downloadFile(req: Request, res: Response) {
  const filePath = getFilePath(req.params.fileId);

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  // Stream file - only small chunks in memory at a time
  const fileStream = createReadStream(filePath);

  try {
    await pipeline(fileStream, res);
  } catch (error) {
    res.status(500).send('Download failed');
  }
}
```

### ✅ Good - Stream Database Results
```typescript
async function exportUsers(req: Request, res: Response) {
  res.setHeader('Content-Type', 'application/json');
  res.write('[');

  let first = true;
  const cursor = User.find().cursor();

  for await (const user of cursor) {
    if (!first) res.write(',');
    res.write(JSON.stringify(user));
    first = false;
  }

  res.write(']');
  res.end();
}
```

---

## 10. Optimizing Async Operations

### ❌ Bad - Unnecessary Awaits
```typescript
async function createOrder(orderData: any) {
  // Waits for each operation sequentially
  await logEvent('order_started', orderData);
  const user = await User.findById(orderData.userId);
  await logEvent('user_fetched', user);
  const product = await Product.findById(orderData.productId);
  await logEvent('product_fetched', product);

  const order = await Order.create({
    userId: user.id,
    productId: product.id,
    amount: product.price,
  });

  await logEvent('order_created', order);

  return order;
}
```

### ✅ Good - Parallel Independent Operations
```typescript
async function createOrder(orderData: any) {
  // Run independent operations in parallel
  const [user, product] = await Promise.all([
    User.findById(orderData.userId),
    Product.findById(orderData.productId),
  ]);

  // Create order (depends on above)
  const order = await Order.create({
    userId: user.id,
    productId: product.id,
    amount: product.price,
  });

  // Log asynchronously (don't wait)
  void logOrderCreated(order); // Fire and forget

  return order;
}

async function logOrderCreated(order: any) {
  try {
    await EventLog.create({
      type: 'order_created',
      orderId: order.id,
      timestamp: new Date(),
    });
  } catch (error) {
    console.error('Failed to log order', error);
  }
}
```

---

## 11. Index Usage

### ❌ Bad - Missing Database Indexes
```typescript
// Mongoose schema without indexes
const userSchema = new Schema({
  email: String, // Frequently queried, but no index
  username: String, // Frequently queried, but no index
  createdAt: Date,
  status: String,
});

// This query will be slow on large collections
const user = await User.findOne({ email: 'user@example.com' });
```

### ✅ Good - Proper Indexes
```typescript
const userSchema = new Schema({
  email: {
    type: String,
    unique: true, // Creates unique index
    index: true,
  },
  username: {
    type: String,
    unique: true,
    index: true,
  },
  createdAt: {
    type: Date,
    index: true, // For sorting/filtering
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'banned'],
    index: true,
  },
});

// Compound index for frequently used combination
userSchema.index({ status: 1, createdAt: -1 });

// Text index for search
userSchema.index({ username: 'text', bio: 'text' });
```

---

## References

- [Node.js Performance Best Practices](https://nodejs.org/en/docs/guides/simple-profiling/)
- [MongoDB Performance Best Practices](https://docs.mongodb.com/manual/administration/analyzing-mongodb-performance/)
- [Express Performance Best Practices](https://expressjs.com/en/advanced/best-practice-performance.html)
