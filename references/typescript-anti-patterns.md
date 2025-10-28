# TypeScript Anti-Patterns for Backend Development

This guide highlights common TypeScript anti-patterns and their better alternatives, specifically for backend/server development.

---

## 1. Overusing the `any` Type

### ❌ Anti-Pattern
```typescript
// Loses all type safety
function processUserData(data: any) {
  return {
    id: data.id,
    name: data.name,
    email: data.email,
  };
}

// No compilation errors, but runtime errors possible
const result = processUserData({ foo: 'bar' });
console.log(result.email.toLowerCase()); // Runtime error!
```

### ✅ Better Approach
```typescript
interface UserData {
  id: string;
  name: string;
  email: string;
}

function processUserData(data: UserData) {
  return {
    id: data.id,
    name: data.name,
    email: data.email,
  };
}

// Compilation error if wrong data shape
const result = processUserData({ foo: 'bar' }); // Error!
```

### ✅ Best - Use `unknown` for Truly Unknown Data
```typescript
import { z } from 'zod';

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
});

function processUserData(data: unknown) {
  // Parse and validate at runtime
  const validated = UserSchema.parse(data);

  return {
    id: validated.id,
    name: validated.name,
    email: validated.email,
  };
}
```

**Key Principle**: You shall (almost) never use `any`. Use `unknown` and validate at boundaries.

---

## 2. Overusing Classes

### ❌ Anti-Pattern - Unnecessary Class for Single Instance
```typescript
// Class with only static methods or single instance
class DatabaseConfig {
  private static host = process.env.DB_HOST;
  private static port = parseInt(process.env.DB_PORT || '5432');

  static getConnectionString(): string {
    return `postgresql://${this.host}:${this.port}`;
  }
}

// Used like this - why a class?
const connectionString = DatabaseConfig.getConnectionString();
```

### ✅ Better - Use Object Literal or Functions
```typescript
// Simple object literal
export const databaseConfig = {
  host: process.env.DB_HOST!,
  port: parseInt(process.env.DB_PORT || '5432'),
  getConnectionString() {
    return `postgresql://${this.host}:${this.port}`;
  },
} as const;

// Or just a function
export function getDatabaseConnectionString(): string {
  const host = process.env.DB_HOST!;
  const port = parseInt(process.env.DB_PORT || '5432');
  return `postgresql://${host}:${port}`;
}
```

### ✅ When Classes Make Sense
```typescript
// Class makes sense when managing state and lifecycle
class DatabaseConnection {
  private pool: Pool | null = null;

  async connect(): Promise<void> {
    this.pool = new Pool({
      connectionString: getDatabaseConnectionString(),
    });
  }

  async query<T>(sql: string, params: any[]): Promise<T[]> {
    if (!this.pool) throw new Error('Not connected');
    const result = await this.pool.query(sql, params);
    return result.rows;
  }

  async close(): Promise<void> {
    await this.pool?.end();
    this.pool = null;
  }
}
```

**Key Principle**: Use classes when you need multiple instances, state management, or lifecycle control. Otherwise, use object literals or functions.

---

## 3. Using the `Function` Type

### ❌ Anti-Pattern - Overly Broad Function Type
```typescript
interface ApiEndpoint {
  path: string;
  handler: Function; // Too broad! Loses all type safety
}

const endpoint: ApiEndpoint = {
  path: '/users',
  handler: (req, res) => {
    // No type checking on parameters or return value
    res.send(req.user.id); // No error if req.user doesn't exist
  },
};
```

### ✅ Better - Specific Function Signature
```typescript
import { Request, Response } from 'express';

type RequestHandler = (req: Request, res: Response) => Promise<void> | void;

interface ApiEndpoint {
  path: string;
  handler: RequestHandler;
}

const endpoint: ApiEndpoint = {
  path: '/users',
  handler: (req, res) => {
    // Type-safe!
    if (!req.user) {
      return res.status(401).send('Unauthorized');
    }
    res.send(req.user.id);
  },
};
```

### ✅ Better - Generic Function Type
```typescript
interface EventHandler<TEvent = any> {
  eventName: string;
  handler: (event: TEvent) => void | Promise<void>;
}

// Specific event types
interface UserCreatedEvent {
  type: 'user.created';
  userId: string;
  email: string;
}

const handler: EventHandler<UserCreatedEvent> = {
  eventName: 'user.created',
  handler: (event) => {
    // event is properly typed!
    console.log(`User ${event.userId} created with email ${event.email}`);
  },
};
```

**Key Principle**: Never use the `Function` type. Always define specific function signatures.

---

## 4. Messing Up with Type Inference

### ❌ Anti-Pattern - Explicitly Typing When Inference Works
```typescript
// Unnecessary type annotations
const users: any[] = await User.find(); // ❌ any defeats the purpose
const count: number = users.length; // ❌ Redundant
const isActive: boolean = true; // ❌ Redundant

function calculateTotal(items: any[]): number { // ❌ any is bad
  return items.reduce((sum: number, item: any) => sum + item.price, 0);
}
```

### ✅ Better - Let TypeScript Infer
```typescript
// Let TypeScript infer types
const users = await User.find(); // TypeScript knows the type from User.find()
const count = users.length; // Inferred as number
const isActive = true; // Inferred as boolean

interface CartItem {
  price: number;
  quantity: number;
}

// Parameter type specified, return type inferred
function calculateTotal(items: CartItem[]) {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}
```

### ✅ When to Explicitly Type
```typescript
// DO explicitly type when defining APIs/contracts
interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
}

interface CreateUserResponse {
  id: string;
  username: string;
  email: string;
}

// Explicit return type for public API
export async function createUser(
  request: CreateUserRequest
): Promise<CreateUserResponse> {
  // Implementation
  const user = await User.create(request);
  return {
    id: user.id,
    username: user.username,
    email: user.email,
  };
}
```

**Key Principle**: Let TypeScript infer types when possible. Explicitly type at API boundaries and public interfaces.

---

## 5. Copy-Pasting Partial Type Definitions

### ❌ Anti-Pattern - Duplicating Type Information
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  createdAt: Date;
}

// Manually duplicating parts of User
interface UserResponse {
  id: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  createdAt: Date;
  // Forgot to exclude password - security issue!
}

// Manually creating update type
interface UpdateUserRequest {
  username?: string;
  email?: string;
  role?: 'user' | 'admin';
  // Inconsistent with User type
}
```

### ✅ Better - Use Utility Types
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  createdAt: Date;
}

// Derive types from User
type UserResponse = Omit<User, 'password'>;

type UpdateUserRequest = Partial<Pick<User, 'username' | 'email' | 'role'>>;

type CreateUserRequest = Omit<User, 'id' | 'createdAt'>;
```

### ✅ Better - Use `typeof` to Extract Types
```typescript
// Extract type from existing object
const config = {
  database: {
    host: 'localhost',
    port: 5432,
    database: 'myapp',
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
} as const;

// Extract type from config object
type Config = typeof config;
type DatabaseConfig = typeof config.database;

// Use in function
function connectToDatabase(config: DatabaseConfig) {
  // config is properly typed!
}
```

### ✅ Better - Use Lookup Types
```typescript
interface ApiResponse {
  data: {
    users: Array<{
      id: string;
      name: string;
    }>;
    pagination: {
      page: number;
      total: number;
    };
  };
  error?: string;
}

// Extract nested types
type User = ApiResponse['data']['users'][number];
type Pagination = ApiResponse['data']['pagination'];

// Use extracted types
function processUsers(users: User[]) {
  // ...
}
```

**Key Principle**: Keep a single source of truth. Derive types using utility types, `typeof`, and lookup types.

---

## 6. Not Using Discriminated Unions

### ❌ Anti-Pattern - Optional Properties Everywhere
```typescript
interface ApiResponse {
  data?: any;
  error?: string;
  loading?: boolean;
}

// Unclear state - can have contradictory combinations
const response: ApiResponse = {
  data: null,
  error: 'Failed',
  loading: true, // Doesn't make sense
};

// Checking becomes messy
if (response.error) {
  console.error(response.error);
} else if (response.data) {
  console.log(response.data);
}
```

### ✅ Better - Discriminated Union
```typescript
type ApiResponse<T> =
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: string };

// Type-safe exhaustive checking
function handleResponse<T>(response: ApiResponse<T>) {
  switch (response.status) {
    case 'loading':
      console.log('Loading...');
      break;
    case 'success':
      console.log(response.data); // TypeScript knows data exists
      break;
    case 'error':
      console.error(response.error); // TypeScript knows error exists
      break;
  }
}
```

### ✅ Example - HTTP Response Types
```typescript
type HttpResponse<T> =
  | { success: true; data: T; statusCode: 200 | 201 }
  | { success: false; error: string; statusCode: 400 | 401 | 403 | 404 | 500 };

async function fetchUser(id: string): Promise<HttpResponse<User>> {
  try {
    const user = await User.findById(id);
    if (!user) {
      return {
        success: false,
        error: 'User not found',
        statusCode: 404,
      };
    }
    return {
      success: true,
      data: user,
      statusCode: 200,
    };
  } catch (error) {
    return {
      success: false,
      error: 'Internal server error',
      statusCode: 500,
    };
  }
}

// Usage
const response = await fetchUser('123');
if (response.success) {
  console.log(response.data); // TypeScript knows data exists
} else {
  console.error(response.error); // TypeScript knows error exists
}
```

**Key Principle**: Use discriminated unions to represent mutually exclusive states.

---

## 7. Inheritance Over Composition

### ❌ Anti-Pattern - Deep Inheritance Hierarchies
```typescript
class BaseService {
  protected logger: Logger;
  constructor() {
    this.logger = new Logger();
  }
}

class DatabaseService extends BaseService {
  protected db: Database;
  constructor() {
    super();
    this.db = new Database();
  }
}

class UserService extends DatabaseService {
  async getUser(id: string) {
    this.logger.info('Fetching user');
    return this.db.query('SELECT * FROM users WHERE id = ?', [id]);
  }
}

// Problems:
// - Tight coupling
// - Hard to test
// - Unclear dependencies
// - Changes to base class affect all children
```

### ✅ Better - Composition with Dependency Injection
```typescript
interface ILogger {
  info(message: string): void;
  error(message: string, error: Error): void;
}

interface IDatabase {
  query<T>(sql: string, params: any[]): Promise<T[]>;
}

class UserService {
  constructor(
    private logger: ILogger,
    private db: IDatabase
  ) {}

  async getUser(id: string) {
    this.logger.info('Fetching user');
    const [user] = await this.db.query<User>(
      'SELECT * FROM users WHERE id = ?',
      [id]
    );
    return user;
  }
}

// Easy to test with mocks
const mockLogger = { info: jest.fn(), error: jest.fn() };
const mockDb = { query: jest.fn().mockResolvedValue([mockUser]) };
const service = new UserService(mockLogger, mockDb);
```

### ✅ Better - Functional Composition
```typescript
type Dependencies = {
  logger: ILogger;
  db: IDatabase;
};

function createUserService(deps: Dependencies) {
  return {
    async getUser(id: string) {
      deps.logger.info('Fetching user');
      const [user] = await deps.db.query<User>(
        'SELECT * FROM users WHERE id = ?',
        [id]
      );
      return user;
    },

    async createUser(data: CreateUserInput) {
      deps.logger.info('Creating user');
      const [user] = await deps.db.query<User>(
        'INSERT INTO users (username, email) VALUES (?, ?) RETURNING *',
        [data.username, data.email]
      );
      return user;
    },
  };
}

// Usage
const userService = createUserService({ logger, db });
```

**Key Principle**: Prefer composition over inheritance. Use dependency injection for better testability.

---

## 8. Not Using `never` for Exhaustive Checks

### ❌ Anti-Pattern - Missing Cases Not Caught
```typescript
type OrderStatus = 'pending' | 'processing' | 'shipped' | 'delivered';

function handleOrderStatus(status: OrderStatus) {
  if (status === 'pending') {
    console.log('Order is pending');
  } else if (status === 'processing') {
    console.log('Order is processing');
  } else if (status === 'shipped') {
    console.log('Order is shipped');
  }
  // Missing 'delivered' case - no error!
}
```

### ✅ Better - Exhaustive Check with `never`
```typescript
type OrderStatus = 'pending' | 'processing' | 'shipped' | 'delivered';

function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${value}`);
}

function handleOrderStatus(status: OrderStatus) {
  switch (status) {
    case 'pending':
      console.log('Order is pending');
      break;
    case 'processing':
      console.log('Order is processing');
      break;
    case 'shipped':
      console.log('Order is shipped');
      break;
    case 'delivered':
      console.log('Order is delivered');
      break;
    default:
      assertNever(status); // Compile error if any case is missing
  }
}

// If we add a new status and forget to handle it:
type OrderStatus = 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
// TypeScript will show an error at assertNever(status)
```

**Key Principle**: Use `never` type for exhaustive checks to catch missing cases at compile time.

---

## 9. Throwing Errors Everywhere

### ❌ Anti-Pattern - Throwing Errors Directly
```typescript
async function getUserById(id: string): Promise<User> {
  const user = await User.findById(id);

  if (!user) {
    throw new Error('User not found'); // Forces try-catch everywhere
  }

  return user;
}

// Forces callers to use try-catch
try {
  const user = await getUserById('123');
  console.log(user.name);
} catch (error) {
  console.error(error);
}
```

### ✅ Better - Result Type Pattern
```typescript
type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

async function getUserById(id: string): Promise<Result<User, string>> {
  const user = await User.findById(id);

  if (!user) {
    return { ok: false, error: 'User not found' };
  }

  return { ok: true, value: user };
}

// Explicit error handling
const result = await getUserById('123');
if (result.ok) {
  console.log(result.value.name);
} else {
  console.error(result.error);
}
```

### ✅ Better - Using neverthrow Library
```typescript
import { Result, ok, err } from 'neverthrow';

async function getUserById(id: string): Promise<Result<User, string>> {
  const user = await User.findById(id);

  if (!user) {
    return err('User not found');
  }

  return ok(user);
}

// Chainable error handling
const result = await getUserById('123')
  .map(user => user.name)
  .mapErr(error => `Failed to get user: ${error}`);

if (result.isOk()) {
  console.log(result.value);
} else {
  console.error(result.error);
}
```

**Key Principle**: Use Result types for expected errors. Reserve exceptions for truly unexpected errors.

---

## 10. Not Using Const Assertions

### ❌ Anti-Pattern - Mutable Inferred Types
```typescript
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000,
  retries: 3,
};

// Type inferred as:
// {
//   apiUrl: string;
//   timeout: number;
//   retries: number;
// }

// Can be mutated
config.apiUrl = 'https://evil.com'; // No error!
config.timeout = 0; // No error!
```

### ✅ Better - Const Assertion for Immutability
```typescript
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000,
  retries: 3,
} as const;

// Type inferred as:
// {
//   readonly apiUrl: "https://api.example.com";
//   readonly timeout: 5000;
//   readonly retries: 3;
// }

config.apiUrl = 'https://evil.com'; // Error: Cannot assign to 'apiUrl' because it is a read-only property
```

### ✅ Use Case - String Literal Arrays
```typescript
// Without const assertion
const roles = ['user', 'admin', 'moderator'];
// Type: string[]

// With const assertion
const roles = ['user', 'admin', 'moderator'] as const;
// Type: readonly ["user", "admin", "moderator"]

type Role = typeof roles[number]; // 'user' | 'admin' | 'moderator'
```

**Key Principle**: Use `as const` for configuration objects and literal arrays to ensure immutability and narrow types.

---

## Summary of Key Principles

1. **Almost never use `any`** - Use `unknown` and validate at boundaries
2. **Don't overuse classes** - Use objects/functions when state/lifecycle isn't needed
3. **Never use `Function` type** - Always define specific signatures
4. **Let TypeScript infer types** - Explicitly type only at API boundaries
5. **Derive types, don't duplicate** - Use utility types, `typeof`, lookup types
6. **Use discriminated unions** - For mutually exclusive states
7. **Prefer composition over inheritance** - Use dependency injection
8. **Use `never` for exhaustive checks** - Catch missing cases at compile time
9. **Use Result types** - For expected errors instead of throwing
10. **Use `as const`** - For immutability and narrow types

## References

- [TypeScript Anti-Patterns by Tomasz Ducin](https://ducin.dev/typescript-anti-patterns)
- [Effective TypeScript Principles in 2025](https://www.dennisokeeffe.com/blog/2025-03-16-effective-typescript-principles-in-2025)
- [TypeScript Style Guide by mkosir](https://mkosir.github.io/typescript-style-guide/)
