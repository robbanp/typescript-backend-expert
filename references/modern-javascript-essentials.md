# Modern JavaScript Essentials (ES6+)

Essential modern JavaScript features that form the foundation for TypeScript backend development.

---

## 1. Arrow Functions

### Basic Syntax

```javascript
// Traditional function
function add(a, b) {
  return a + b;
}

// Arrow function
const add = (a, b) => a + b;

// With block body
const multiply = (a, b) => {
  const result = a * b;
  return result;
};

// Single parameter (parentheses optional)
const double = x => x * 2;

// No parameters
const random = () => Math.random();
```

### Lexical `this` Binding

```javascript
// Problem with traditional functions
class UserService {
  constructor() {
    this.users = [];
  }

  fetchUsers() {
    // ❌ 'this' is undefined in callback
    fetch('/api/users')
      .then(function(response) {
        this.users = response.data; // Error!
      });
  }
}

// Solution 1: Arrow function
class UserService {
  constructor() {
    this.users = [];
  }

  fetchUsers() {
    // ✅ Arrow function inherits 'this' from enclosing scope
    fetch('/api/users')
      .then(response => {
        this.users = response.data; // Works!
      });
  }
}

// Solution 2: Bind
fetchUsers() {
  fetch('/api/users')
    .then(function(response) {
      this.users = response.data;
    }.bind(this));
}
```

### Backend Use Cases

```typescript
// Express route handlers
app.get('/users', (req, res) => {
  res.json(users);
});

// Array operations
const activeUsers = users.filter(user => user.isActive);
const userIds = users.map(user => user.id);

// Event handlers
eventEmitter.on('user:created', user => {
  logger.info(`User created: ${user.id}`);
});

// Async operations
const fetchUser = async (id) => {
  const user = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  return user;
};
```

---

## 2. Destructuring

### Object Destructuring

```javascript
// Basic destructuring
const user = { id: 1, name: 'Alice', email: 'alice@example.com' };
const { id, name, email } = user;

console.log(name); // 'Alice'

// Rename variables
const { id: userId, name: userName } = user;

console.log(userId); // 1

// Default values
const { age = 25 } = user;

console.log(age); // 25 (default)

// Nested destructuring
const user = {
  profile: {
    name: 'Alice',
    settings: {
      theme: 'dark'
    }
  }
};

const { profile: { name, settings: { theme } } } = user;

console.log(theme); // 'dark'

// Rest properties
const { id, ...rest } = user;

console.log(rest); // { name: 'Alice', email: 'alice@example.com' }
```

### Array Destructuring

```javascript
// Basic array destructuring
const numbers = [1, 2, 3, 4, 5];
const [first, second] = numbers;

console.log(first); // 1

// Skip elements
const [, , third] = numbers;

console.log(third); // 3

// Rest elements
const [head, ...tail] = numbers;

console.log(tail); // [2, 3, 4, 5]

// Swap variables
let a = 1;
let b = 2;
[a, b] = [b, a];

console.log(a); // 2
console.log(b); // 1
```

### Backend Use Cases

```typescript
// Express request destructuring
app.post('/users', (req, res) => {
  const { name, email, age } = req.body;
  const { authorization } = req.headers;
  // ...
});

// Fastify route params
app.get('/users/:id', async (request, reply) => {
  const { id } = request.params;
  const { page = 1, limit = 10 } = request.query;
  // ...
});

// Function parameters
function createUser({ name, email, age, role = 'user' }) {
  return { name, email, age, role };
}

// Database results
const [user] = await db.query('SELECT * FROM users WHERE id = $1', [id]);

// Config destructuring
const {
  DB_HOST: host,
  DB_PORT: port,
  DB_NAME: database
} = process.env;
```

---

## 3. Spread and Rest Operators

### Spread Operator (...)

```javascript
// Array spreading
const arr1 = [1, 2, 3];
const arr2 = [4, 5, 6];
const combined = [...arr1, ...arr2]; // [1, 2, 3, 4, 5, 6]

// Object spreading
const user = { name: 'Alice', age: 30 };
const updatedUser = { ...user, age: 31 }; // { name: 'Alice', age: 31 }

// Merge objects
const defaults = { theme: 'light', notifications: true };
const userSettings = { theme: 'dark' };
const settings = { ...defaults, ...userSettings }; // { theme: 'dark', notifications: true }

// Function arguments
const numbers = [1, 2, 3];
Math.max(...numbers); // 3

// Clone arrays/objects (shallow)
const clone = [...arr1];
const userClone = { ...user };
```

### Rest Parameters

```javascript
// Rest in function parameters
function sum(...numbers) {
  return numbers.reduce((total, num) => total + num, 0);
}

sum(1, 2, 3, 4); // 10

// Mix with other parameters
function logMessage(level, ...messages) {
  console.log(`[${level}]`, ...messages);
}

logMessage('INFO', 'User', 'created', 'successfully');

// Rest in destructuring
const { id, ...userData } = user;
```

### Backend Use Cases

```typescript
// Merge configurations
const defaultConfig = {
  port: 3000,
  host: 'localhost',
  db: { pool: 10 }
};

const userConfig = {
  port: 8080,
  db: { pool: 20 }
};

const config = {
  ...defaultConfig,
  ...userConfig,
  db: { ...defaultConfig.db, ...userConfig.db }
};

// Clone and update
const updateUser = (user, updates) => {
  return { ...user, ...updates, updatedAt: new Date() };
};

// Remove sensitive fields
const sanitizeUser = (user) => {
  const { password, secret, ...safeUser } = user;
  return safeUser;
};

// Variadic functions
function createMiddlewareChain(...middlewares) {
  return (req, res, next) => {
    let index = 0;

    function dispatch() {
      if (index >= middlewares.length) return next();
      const middleware = middlewares[index++];
      middleware(req, res, dispatch);
    }

    dispatch();
  };
}

// Merge query parameters
function buildQuery(baseQuery, ...conditions) {
  return conditions.reduce((query, condition) => {
    return { ...query, ...condition };
  }, baseQuery);
}
```

---

## 4. Template Literals

### Basic Template Literals

```javascript
// String interpolation
const name = 'Alice';
const greeting = `Hello, ${name}!`;

// Multiline strings
const message = `
  This is a multiline
  string that spans
  multiple lines.
`;

// Expression evaluation
const a = 5;
const b = 10;
console.log(`Sum: ${a + b}`); // "Sum: 15"

// Function calls
console.log(`User: ${getUser().name}`);
```

### Tagged Templates

```javascript
// Custom tag function
function sql(strings, ...values) {
  let query = strings[0];

  values.forEach((value, i) => {
    query += `$${i + 1}` + strings[i + 1];
  });

  return { text: query, values };
}

// Usage
const userId = '123';
const query = sql`SELECT * FROM users WHERE id = ${userId}`;
// { text: 'SELECT * FROM users WHERE id = $1', values: ['123'] }

// HTML escaping
function html(strings, ...values) {
  return strings.reduce((result, str, i) => {
    const value = values[i - 1];
    const escaped = String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return result + escaped + str;
  });
}

const userInput = '<script>alert("XSS")</script>';
const safe = html`<div>${userInput}</div>`;
// "<div>&lt;script&gt;alert("XSS")&lt;/script&gt;</div>"
```

### Backend Use Cases

```typescript
// Logging with context
logger.info(`User ${userId} created order ${orderId}`);

// SQL queries with tagged templates
const getUserQuery = (id: string) => sql`
  SELECT id, name, email
  FROM users
  WHERE id = ${id}
`;

// Error messages
throw new Error(`User with email ${email} already exists`);

// Dynamic routes
const apiUrl = `${baseUrl}/api/v${version}/users/${userId}`;

// Email templates
const emailBody = `
  Hi ${user.name},

  Welcome to our platform!

  Your account has been created successfully.

  Best regards,
  The Team
`;

// Query string building
const queryString = `?page=${page}&limit=${limit}&sort=${sort}`;

// Markdown/HTML generation
const markdown = `
# ${title}

Created by: ${author}
Date: ${date}

${content}
`;
```

---

## 5. Enhanced Object Literals

### Shorthand Property Names

```javascript
// Before ES6
const name = 'Alice';
const age = 30;
const user = {
  name: name,
  age: age
};

// ES6+ shorthand
const user = { name, age }; // { name: 'Alice', age: 30 }
```

### Shorthand Method Names

```javascript
// Before ES6
const obj = {
  method: function() {
    return 'Hello';
  }
};

// ES6+ shorthand
const obj = {
  method() {
    return 'Hello';
  },

  async fetchData() {
    return await fetch('/api/data');
  }
};
```

### Computed Property Names

```javascript
// Dynamic property names
const key = 'userId';
const value = '123';

const obj = {
  [key]: value // { userId: '123' }
};

// With expressions
const prefix = 'user';
const obj = {
  [`${prefix}Name`]: 'Alice',
  [`${prefix}Age`]: 30
};
// { userName: 'Alice', userAge: 30 }

// From function
function createKey(type, id) {
  return `${type}_${id}`;
}

const data = {
  [createKey('user', 123)]: userData
};
```

### Backend Use Cases

```typescript
// Response builders
function createResponse(data, status = 200) {
  return {
    data,
    status,
    timestamp: Date.now()
  };
}

// Service class
class UserService {
  constructor(repository, logger) {
    this.repository = repository;
    this.logger = logger;
  }

  async findById(id) {
    this.logger.info(`Finding user ${id}`);
    return this.repository.findById(id);
  }

  async create(userData) {
    return this.repository.create({
      ...userData,
      createdAt: new Date(),
      updatedAt: new Date()
    });
  }
}

// Dynamic query building
function buildWhereClause(filters) {
  const conditions = {};

  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined) {
      conditions[key] = value;
    }
  }

  return conditions;
}

// Event data
const eventType = 'user';
const action = 'created';

const eventData = {
  [`${eventType}:${action}`]: {
    userId: user.id,
    timestamp: Date.now()
  }
};
```

---

## 6. Async/Await Patterns

### Basic Async/Await

```javascript
// Promise-based
function fetchUser(id) {
  return fetch(`/api/users/${id}`)
    .then(response => response.json())
    .then(user => user)
    .catch(error => console.error(error));
}

// Async/await
async function fetchUser(id) {
  try {
    const response = await fetch(`/api/users/${id}`);
    const user = await response.json();
    return user;
  } catch (error) {
    console.error(error);
    throw error;
  }
}
```

### Parallel vs Sequential

```javascript
// Sequential (slow) - 6 seconds total
async function fetchAllSequential() {
  const users = await fetchUsers();      // 2 seconds
  const posts = await fetchPosts();      // 2 seconds
  const comments = await fetchComments(); // 2 seconds

  return { users, posts, comments };
}

// Parallel (fast) - 2 seconds total
async function fetchAllParallel() {
  const [users, posts, comments] = await Promise.all([
    fetchUsers(),      // Start all
    fetchPosts(),      // at the same
    fetchComments()    // time
  ]);

  return { users, posts, comments };
}

// Parallel with individual error handling
async function fetchAllWithFallback() {
  const results = await Promise.allSettled([
    fetchUsers(),
    fetchPosts(),
    fetchComments()
  ]);

  return {
    users: results[0].status === 'fulfilled' ? results[0].value : [],
    posts: results[1].status === 'fulfilled' ? results[1].value : [],
    comments: results[2].status === 'fulfilled' ? results[2].value : []
  };
}
```

### Backend Use Cases

```typescript
// Express route handler
app.get('/users/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const user = await userService.findById(id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ data: user });
  } catch (error) {
    next(error);
  }
});

// Service method with multiple operations
async function createOrder(userId, items) {
  // Sequential - each depends on previous
  const user = await userRepo.findById(userId);

  if (!user) {
    throw new Error('User not found');
  }

  const validatedItems = await validateItems(items);
  const order = await orderRepo.create({
    userId,
    items: validatedItems,
    total: calculateTotal(validatedItems)
  });

  await inventoryService.reserveItems(validatedItems);
  await emailService.sendOrderConfirmation(user.email, order);

  return order;
}

// Parallel operations when independent
async function getUserDashboard(userId) {
  const [user, orders, notifications, stats] = await Promise.all([
    userRepo.findById(userId),
    orderRepo.findByUserId(userId),
    notificationRepo.findByUserId(userId),
    statsService.getUserStats(userId)
  ]);

  return { user, orders, notifications, stats };
}

// Async iteration
async function processUsers(userIds) {
  for (const userId of userIds) {
    await processUser(userId); // Sequential processing
  }
}

// Parallel processing with concurrency limit
async function processUsersInBatches(userIds, batchSize = 10) {
  for (let i = 0; i < userIds.length; i += batchSize) {
    const batch = userIds.slice(i, i + batchSize);
    await Promise.all(batch.map(id => processUser(id)));
  }
}
```

---

## 7. Functional Array Methods

### map, filter, reduce

```javascript
const users = [
  { id: 1, name: 'Alice', age: 30, active: true },
  { id: 2, name: 'Bob', age: 25, active: false },
  { id: 3, name: 'Charlie', age: 35, active: true }
];

// map - transform each element
const names = users.map(user => user.name);
// ['Alice', 'Bob', 'Charlie']

// filter - keep elements matching condition
const activeUsers = users.filter(user => user.active);
// [{ id: 1, ... }, { id: 3, ... }]

// reduce - accumulate to single value
const totalAge = users.reduce((sum, user) => sum + user.age, 0);
// 90

// Chaining
const activeUserNames = users
  .filter(user => user.active)
  .map(user => user.name);
// ['Alice', 'Charlie']

// Complex reduce
const usersByStatus = users.reduce((acc, user) => {
  const key = user.active ? 'active' : 'inactive';
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});
// { active: [...], inactive: [...] }
```

### find, findIndex, some, every

```javascript
// find - first matching element
const user = users.find(u => u.id === 2);

// findIndex - index of first match
const index = users.findIndex(u => u.id === 2);

// some - at least one matches
const hasActiveUsers = users.some(u => u.active); // true

// every - all match
const allActive = users.every(u => u.active); // false
```

### Backend Use Cases

```typescript
// Transform database results
const sanitizedUsers = users.map(user => ({
  id: user.id,
  name: user.name,
  email: user.email
  // password excluded
}));

// Filter by permissions
const visiblePosts = posts.filter(post =>
  post.isPublic || post.authorId === currentUserId
);

// Aggregate data
const orderTotal = orderItems.reduce((total, item) => {
  return total + (item.price * item.quantity);
}, 0);

// Group by category
const groupedProducts = products.reduce((groups, product) => {
  const category = product.category;
  groups[category] = groups[category] || [];
  groups[category].push(product);
  return groups;
}, {});

// Validation
const allValid = items.every(item => item.quantity > 0 && item.price >= 0);

// Check permissions
const hasPermission = user.roles.some(role =>
  ['admin', 'moderator'].includes(role)
);

// Extract IDs
const userIds = users.map(u => u.id);

// Build lookup map
const usersById = users.reduce((map, user) => {
  map[user.id] = user;
  return map;
}, {});
```

---

## 8. Optional Chaining & Nullish Coalescing

### Optional Chaining (?.)

```javascript
// Without optional chaining
const street = user && user.address && user.address.street;

// With optional chaining
const street = user?.address?.street;

// Array access
const firstPost = user?.posts?.[0];

// Method calls
const result = obj?.method?.();

// With function calls
const value = getUser()?.profile?.settings?.theme;
```

### Nullish Coalescing (??)

```javascript
// Using || (can have unexpected behavior)
const port = process.env.PORT || 3000;
// Problem: if PORT is 0, uses 3000

// Using ?? (only null/undefined trigger default)
const port = process.env.PORT ?? 3000;
// 0 is valid, only null/undefined use 3000

// Combine with optional chaining
const theme = user?.settings?.theme ?? 'light';
```

### Backend Use Cases

```typescript
// Safe property access
const email = req.body?.user?.email;

// Config with defaults
const dbConfig = {
  host: process.env.DB_HOST ?? 'localhost',
  port: parseInt(process.env.DB_PORT ?? '5432'),
  pool: parseInt(process.env.DB_POOL ?? '10')
};

// Nested database results
const userName = result?.rows?.[0]?.name;

// Optional middleware
const authMiddleware = config?.security?.enabled
  ? authenticate
  : (req, res, next) => next();

// Safe method invocation
await logger?.info?.('User created', { userId });

// Query parameters with defaults
const page = parseInt(req.query?.page) ?? 1;
const limit = parseInt(req.query?.limit) ?? 10;
```

---

## References

- [MDN JavaScript Guide](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide)
- [ES6 Features](http://es6-features.org/)
- [JavaScript.info](https://javascript.info/)
- [You Don't Know JS](https://github.com/getify/You-Dont-Know-JS)
