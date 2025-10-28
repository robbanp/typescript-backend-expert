# Type Safety Checklist for TypeScript Backend Applications

## TypeScript Configuration

### Strict Mode Configuration
- [ ] `strict: true` enabled in tsconfig.json
- [ ] `noImplicitAny: true`
- [ ] `strictNullChecks: true`
- [ ] `strictFunctionTypes: true`
- [ ] `strictBindCallApply: true`
- [ ] `strictPropertyInitialization: true`
- [ ] `noImplicitThis: true`
- [ ] `alwaysStrict: true`

**Recommended tsconfig.json for Backend:**
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noPropertyAccessFromIndexSignature": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```

---

## Type Definitions

### Request/Response Types
- [ ] All API request bodies typed
- [ ] All API responses typed
- [ ] Query parameters typed
- [ ] Route parameters typed
- [ ] Headers typed where used

**Example - Express with TypeScript:**
```typescript
import { Request, Response, NextFunction } from 'express';

// Define request body interface
interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  role?: 'user' | 'admin';
}

// Define response interface
interface UserResponse {
  id: string;
  username: string;
  email: string;
  role: string;
  createdAt: string;
}

// Type-safe request handler
async function createUser(
  req: Request<{}, UserResponse, CreateUserRequest>,
  res: Response<UserResponse>
): Promise<void> {
  const { username, email, password, role = 'user' } = req.body;

  const user = await User.create({
    username,
    email,
    password: await hashPassword(password),
    role,
  });

  res.status(201).json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt.toISOString(),
  });
}
```

**Example - Fastify with TypeScript:**
```typescript
import { FastifyRequest, FastifyReply } from 'fastify';

interface CreateUserBody {
  username: string;
  email: string;
  password: string;
}

interface UserParams {
  id: string;
}

interface UserQuery {
  includeOrders?: boolean;
}

// Type-safe route handler
async function getUser(
  request: FastifyRequest<{
    Params: UserParams;
    Querystring: UserQuery;
  }>,
  reply: FastifyReply
): Promise<void> {
  const { id } = request.params;
  const { includeOrders } = request.query;

  const user = await User.findById(id);
  if (!user) {
    return reply.status(404).send({ error: 'User not found' });
  }

  const response: any = {
    id: user.id,
    username: user.username,
    email: user.email,
  };

  if (includeOrders) {
    response.orders = await Order.find({ userId: id });
  }

  reply.send(response);
}
```

### Database Model Types
- [ ] ORM/ODM models fully typed
- [ ] Mongoose schemas with TypeScript interfaces
- [ ] Prisma or TypeORM types generated
- [ ] Database query results typed

**Example - Mongoose with TypeScript:**
```typescript
import { Schema, model, Document, Model } from 'mongoose';

// Document interface (what the model returns)
export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

// Model interface (static methods)
export interface IUserModel extends Model<IUser> {
  findByEmail(email: string): Promise<IUser | null>;
}

const userSchema = new Schema<IUser, IUserModel>({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
}, {
  timestamps: true,
});

// Instance method
userSchema.methods.comparePassword = async function(
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

// Static method
userSchema.statics.findByEmail = function(email: string) {
  return this.findOne({ email });
};

export const User = model<IUser, IUserModel>('User', userSchema);
```

**Example - Prisma (auto-generated types):**
```typescript
import { PrismaClient, User, Prisma } from '@prisma/client';

const prisma = new PrismaClient();

// Types are automatically generated from schema
async function createUser(data: Prisma.UserCreateInput): Promise<User> {
  return prisma.user.create({ data });
}

async function getUserWithOrders(userId: string) {
  // Type inference for includes
  return prisma.user.findUnique({
    where: { id: userId },
    include: {
      orders: true,
      profile: true,
    },
  });
}

// Return type is automatically inferred:
// User & { orders: Order[]; profile: Profile | null }
```

---

## Avoiding `any` Type

### No Implicit Any
- [ ] No `any` type without explicit justification
- [ ] Use `unknown` for truly unknown types
- [ ] Proper type guards for `unknown` types
- [ ] Document why `any` is used when unavoidable

**Example - Replacing `any` with `unknown`:**
```typescript
// ❌ Bad - using any
function processData(data: any): void {
  console.log(data.value); // No type safety
}

// ✅ Good - using unknown with type guard
function processData(data: unknown): void {
  if (isValidData(data)) {
    console.log(data.value); // Type-safe after guard
  }
}

function isValidData(data: unknown): data is { value: string } {
  return (
    typeof data === 'object' &&
    data !== null &&
    'value' in data &&
    typeof (data as any).value === 'string'
  );
}
```

### External Data Validation
- [ ] Runtime validation for external data (requests, APIs)
- [ ] Validation library (Zod, Joi, class-validator)
- [ ] Parse, don't cast

**Example - Zod for Runtime Validation:**
```typescript
import { z } from 'zod';

// Define schema
const CreateUserSchema = z.object({
  username: z.string().min(3).max(30),
  email: z.string().email(),
  password: z.string().min(8),
  age: z.number().int().positive().optional(),
  role: z.enum(['user', 'admin']).default('user'),
});

// Infer TypeScript type from schema
type CreateUserInput = z.infer<typeof CreateUserSchema>;

// Validation middleware
function validateBody<T extends z.ZodType>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors,
        });
      }
      next(error);
    }
  };
}

// Usage
app.post('/api/users',
  validateBody(CreateUserSchema),
  async (req: Request<{}, {}, CreateUserInput>, res) => {
    // req.body is now type-safe and validated
    const user = await createUser(req.body);
    res.json(user);
  }
);
```

---

## Generic Types

### Proper Generic Usage
- [ ] Reusable functions use generics
- [ ] Generic constraints where appropriate
- [ ] Avoid over-generalization

**Example - Generic API Response:**
```typescript
interface ApiResponse<T> {
  data: T;
  status: 'success' | 'error';
  message?: string;
  timestamp: string;
}

interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    hasMore: boolean;
  };
}

// Generic response builder
function createResponse<T>(data: T, message?: string): ApiResponse<T> {
  return {
    data,
    status: 'success',
    message,
    timestamp: new Date().toISOString(),
  };
}

// Usage
const userResponse = createResponse<UserResponse>(user);
const usersResponse = createResponse<UserResponse[]>(users);
```

**Example - Generic Repository Pattern:**
```typescript
interface BaseEntity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}

class Repository<T extends BaseEntity> {
  constructor(private model: Model<T>) {}

  async findById(id: string): Promise<T | null> {
    return this.model.findById(id).exec();
  }

  async findAll(filter: Partial<T> = {}): Promise<T[]> {
    return this.model.find(filter as any).exec();
  }

  async create(data: Omit<T, keyof BaseEntity>): Promise<T> {
    return this.model.create(data as any);
  }

  async update(id: string, data: Partial<T>): Promise<T | null> {
    return this.model.findByIdAndUpdate(id, data, { new: true }).exec();
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.model.findByIdAndDelete(id).exec();
    return result !== null;
  }
}

// Usage
const userRepository = new Repository<IUser>(User);
const orderRepository = new Repository<IOrder>(Order);
```

---

## Utility Types

### Built-in Utility Types
- [ ] Use `Partial<T>` for optional properties
- [ ] Use `Pick<T, K>` for selecting properties
- [ ] Use `Omit<T, K>` for excluding properties
- [ ] Use `Record<K, T>` for key-value maps
- [ ] Use `Required<T>` for making properties required
- [ ] Use `Readonly<T>` for immutable objects

**Example - Utility Types in Action:**
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  createdAt: Date;
}

// Public user data (omit password)
type PublicUser = Omit<User, 'password'>;

// User creation input (omit generated fields)
type CreateUserInput = Omit<User, 'id' | 'createdAt'>;

// User update input (all fields optional except id)
type UpdateUserInput = Partial<Omit<User, 'id'>>;

// Only email and username
type UserCredentials = Pick<User, 'email' | 'password'>;

// Read-only user
type ImmutableUser = Readonly<User>;

// Role-based permissions
type Permissions = Record<User['role'], string[]>;
const permissions: Permissions = {
  user: ['read:own', 'write:own'],
  admin: ['read:all', 'write:all', 'delete:all'],
};
```

---

## Async/Promise Types

### Proper Promise Typing
- [ ] All async functions return typed Promises
- [ ] Error handling typed
- [ ] No unhandled promise rejections

**Example - Typed Async Functions:**
```typescript
// Explicitly typed Promise return
async function fetchUser(id: string): Promise<User | null> {
  try {
    const user = await User.findById(id);
    return user;
  } catch (error) {
    logger.error('Failed to fetch user', { error, userId: id });
    return null;
  }
}

// Generic async function
async function fetchWithRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3
): Promise<T> {
  let lastError: Error;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      await sleep(Math.pow(2, i) * 1000); // Exponential backoff
    }
  }

  throw lastError!;
}

// Usage
const user = await fetchWithRetry(() => fetchUser(userId));
```

---

## Type Guards and Narrowing

### Custom Type Guards
- [ ] Type guards for discriminated unions
- [ ] Type guards for external data
- [ ] Proper narrowing of union types

**Example - Type Guards:**
```typescript
// Discriminated union
type ApiResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

// Type guard
function isSuccess<T>(result: ApiResult<T>): result is { success: true; data: T } {
  return result.success === true;
}

// Usage
async function handleApiCall<T>(result: ApiResult<T>): Promise<void> {
  if (isSuccess(result)) {
    console.log(result.data); // TypeScript knows data exists
  } else {
    console.error(result.error); // TypeScript knows error exists
  }
}

// Type guard for object shape
interface ErrorResponse {
  error: string;
  code: number;
}

function isErrorResponse(obj: unknown): obj is ErrorResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'error' in obj &&
    'code' in obj &&
    typeof (obj as any).error === 'string' &&
    typeof (obj as any).code === 'number'
  );
}
```

---

## Enum vs Union Types

### When to Use Each
- [ ] Use string literal unions for small, related values
- [ ] Use enums for larger sets or when reverse mapping needed
- [ ] Use const enums for performance (no runtime)

**Example - Union Types vs Enums:**
```typescript
// ✅ Good - String literal union for simple cases
type UserRole = 'user' | 'admin' | 'moderator';

function hasPermission(role: UserRole, action: string): boolean {
  // Type-safe without enum
  if (role === 'admin') return true;
  // ...
}

// ✅ Good - Enum for complex cases
enum OrderStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  SHIPPED = 'SHIPPED',
  DELIVERED = 'DELIVERED',
  CANCELLED = 'CANCELLED',
}

// Can iterate over enum values
const allStatuses = Object.values(OrderStatus);

// ✅ Good - Const enum (no runtime code)
const enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
}

// Inlined at compile time
const method = HttpMethod.GET; // becomes const method = "GET"
```

---

## Middleware Typing

### Type-Safe Middleware
- [ ] Middleware properly typed
- [ ] Extended request objects typed
- [ ] Middleware composition typed

**Example - Express Middleware:**
```typescript
import { Request, Response, NextFunction } from 'express';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: string;
      };
      requestId: string;
    }
  }
}

// Type-safe middleware
function authenticate(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded; // Type-safe assignment
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Middleware with options
interface RateLimitOptions {
  windowMs: number;
  max: number;
}

function rateLimit(options: RateLimitOptions) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Implementation
    next();
  };
}
```

---

## Error Handling Types

### Custom Error Classes
- [ ] Custom error classes extend Error
- [ ] Error types for different scenarios
- [ ] Type-safe error handling

**Example - Typed Errors:**
```typescript
// Base application error
class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number,
    public isOperational: boolean = true
  ) {
    super(message);
    Object.setPrototypeOf(this, AppError.prototype);
    Error.captureStackTrace(this, this.constructor);
  }
}

// Specific error types
class ValidationError extends AppError {
  constructor(message: string, public field?: string) {
    super(message, 400);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

class NotFoundError extends AppError {
  constructor(resource: string, id: string) {
    super(`${resource} with id ${id} not found`, 404);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

class UnauthorizedError extends AppError {
  constructor(message: string = 'Unauthorized') {
    super(message, 401);
    Object.setPrototypeOf(this, UnauthorizedError.prototype);
  }
}

// Type-safe error handler
function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
    });
    return;
  }

  // Unexpected error
  logger.error('Unexpected error', { error: err });
  res.status(500).json({
    status: 'error',
    message: 'Internal server error',
  });
}
```

---

## Type Testing

### Testing Types
- [ ] Use type assertions in tests
- [ ] Test type narrowing
- [ ] Use `@ts-expect-error` for negative tests

**Example - Type Tests:**
```typescript
// Type test using conditional types
type Expect<T extends true> = T;
type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2
  ? true
  : false;

// Test cases
type TestCases = [
  Expect<Equal<CreateUserInput, Omit<User, 'id' | 'createdAt'>>>,
  Expect<Equal<PublicUser, Omit<User, 'password'>>>,
];

// Runtime type checking in tests
import { expect } from 'chai';

describe('Type Guards', () => {
  it('should narrow type correctly', () => {
    const result: ApiResult<User> = {
      success: true,
      data: mockUser,
    };

    if (isSuccess(result)) {
      expect(result.data).to.exist;
      // @ts-expect-error - error should not exist
      expect(result.error).to.be.undefined;
    }
  });
});
```

---

## Advanced Best Practices

### Const Assertions for Immutability
- [ ] Use `as const` for configuration objects
- [ ] Use `as const` for string literal arrays
- [ ] Leverage const assertions for narrow types

**Example - Configuration with Const Assertion:**
```typescript
// ❌ Bad - Mutable, wide types
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000,
  endpoints: ['users', 'orders', 'products']
};
// Type: { apiUrl: string; timeout: number; endpoints: string[] }

// ✅ Good - Immutable, narrow types
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000,
  endpoints: ['users', 'orders', 'products']
} as const;
// Type: { readonly apiUrl: "https://api.example.com"; readonly timeout: 5000; readonly endpoints: readonly ["users", "orders", "products"] }

type Endpoint = typeof config.endpoints[number]; // 'users' | 'orders' | 'products'
```

### Result Types for Error Handling
- [ ] Use Result types for expected errors
- [ ] Reserve exceptions for unexpected errors
- [ ] Consider `neverthrow` library for functional error handling

**Example - Result Type Pattern:**
```typescript
type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

async function fetchUser(id: string): Promise<Result<User, string>> {
  try {
    const user = await User.findById(id);
    if (!user) {
      return { ok: false, error: 'User not found' };
    }
    return { ok: true, value: user };
  } catch (error) {
    return { ok: false, error: 'Database error' };
  }
}

// Usage - explicit error handling
const result = await fetchUser('123');
if (result.ok) {
  console.log(result.value.name);
} else {
  console.error(result.error);
}
```

### Exhaustive Checks with `never`
- [ ] Use `never` type for exhaustive switch/if checks
- [ ] Catch missing cases at compile time
- [ ] Add `assertNever` utility function

**Example - Exhaustive Checking:**
```typescript
function assertNever(value: never): never {
  throw new Error(`Unhandled value: ${value}`);
}

type OrderStatus = 'pending' | 'processing' | 'shipped' | 'delivered';

function processOrder(status: OrderStatus) {
  switch (status) {
    case 'pending':
      return handlePending();
    case 'processing':
      return handleProcessing();
    case 'shipped':
      return handleShipped();
    case 'delivered':
      return handleDelivered();
    default:
      return assertNever(status); // Compile error if any case missing
  }
}
```

### Composition Over Inheritance
- [ ] Prefer composition and dependency injection
- [ ] Avoid deep inheritance hierarchies
- [ ] Use interfaces to define contracts
- [ ] Make dependencies explicit

**Example - Dependency Injection:**
```typescript
// ❌ Bad - Inheritance
class BaseService {
  protected logger: Logger;
  constructor() {
    this.logger = new Logger();
  }
}

class UserService extends BaseService {
  async getUser(id: string) {
    this.logger.info('Fetching user');
    return User.findById(id);
  }
}

// ✅ Good - Composition with DI
interface ILogger {
  info(message: string): void;
  error(message: string, error: Error): void;
}

class UserService {
  constructor(private logger: ILogger) {}

  async getUser(id: string) {
    this.logger.info('Fetching user');
    return User.findById(id);
  }
}

// Easy to test with mocks
const mockLogger = { info: jest.fn(), error: jest.fn() };
const service = new UserService(mockLogger);
```

### Discriminated Unions Over Optional Properties
- [ ] Use discriminated unions for mutually exclusive states
- [ ] Avoid multiple optional properties that represent states
- [ ] Use tag property for discrimination

**Example - Discriminated Unions:**
```typescript
// ❌ Bad - Optional properties
interface ApiResponse {
  data?: any;
  error?: string;
  loading?: boolean;
}

// ✅ Good - Discriminated union
type ApiResponse<T> =
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: string };

function handleResponse<T>(response: ApiResponse<T>) {
  switch (response.status) {
    case 'loading':
      return showSpinner();
    case 'success':
      return displayData(response.data); // TypeScript knows data exists
    case 'error':
      return showError(response.error); // TypeScript knows error exists
  }
}
```

### Schema-Based Type Generation
- [ ] Define schemas as source of truth (Zod, Joi)
- [ ] Parse and validate at system boundaries
- [ ] Generate TypeScript types from schemas
- [ ] Keep validation and types in sync

**Example - Zod Schema as Source of Truth:**
```typescript
import { z } from 'zod';

// Schema is the source of truth
const UserSchema = z.object({
  id: z.string().uuid(),
  username: z.string().min(3).max(30),
  email: z.string().email(),
  role: z.enum(['user', 'admin']),
  createdAt: z.date(),
});

// Generate TypeScript type from schema
type User = z.infer<typeof UserSchema>;

// Validation at boundary
export async function createUser(data: unknown): Promise<User> {
  // Parse and validate
  const validated = UserSchema.parse(data);

  // validated is typed as User
  const user = await User.create(validated);
  return user;
}

// Create variations
const CreateUserSchema = UserSchema.omit({ id: true, createdAt: true });
type CreateUserInput = z.infer<typeof CreateUserSchema>;

const UpdateUserSchema = UserSchema.partial().pick({
  username: true,
  email: true,
});
type UpdateUserInput = z.infer<typeof UpdateUserSchema>;
```

### Type Narrowing and Guards
- [ ] Use type guards for complex narrowing
- [ ] Leverage control flow analysis
- [ ] Use `in` operator for property checks
- [ ] Use `typeof` and `instanceof` appropriately

**Example - Advanced Type Guards:**
```typescript
// Type guard for discriminated union
type DbResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

function isSuccess<T>(result: DbResult<T>): result is { success: true; data: T } {
  return result.success === true;
}

// Usage
const result = await fetchData();
if (isSuccess(result)) {
  console.log(result.data); // TypeScript knows data exists
}

// Property checking with 'in' operator
type Cat = { type: 'cat'; meow: () => void };
type Dog = { type: 'dog'; bark: () => void };
type Animal = Cat | Dog;

function handleAnimal(animal: Animal) {
  if ('meow' in animal) {
    animal.meow(); // TypeScript knows it's a Cat
  } else {
    animal.bark(); // TypeScript knows it's a Dog
  }
}
```

### Function Design Principles
- [ ] Functions should be pure when possible
- [ ] Single responsibility principle
- [ ] Accept at least one argument (avoid side-effect-only functions)
- [ ] Return meaningful data
- [ ] Keep functions small and focused

**Example - Pure Functions:**
```typescript
// ❌ Bad - Impure function with side effects
let userCache: Map<string, User> = new Map();

function getUser(id: string): User | undefined {
  if (userCache.has(id)) {
    return userCache.get(id);
  }
  const user = fetchUserFromDb(id);
  userCache.set(id, user); // Side effect
  return user;
}

// ✅ Good - Pure function
function getUserFromCache(
  id: string,
  cache: Map<string, User>
): User | undefined {
  return cache.get(id);
}

function addUserToCache(
  cache: Map<string, User>,
  id: string,
  user: User
): Map<string, User> {
  const newCache = new Map(cache);
  newCache.set(id, user);
  return newCache;
}
```

### Naming Conventions
- [ ] Variables and functions: `camelCase`
- [ ] Constants: `UPPER_SNAKE_CASE`
- [ ] Types and interfaces: `PascalCase`
- [ ] Generic type parameters: Start with `T` (e.g., `TRequest`, `TResponse`)
- [ ] Private properties: Consider `_prefix` or `#private` fields
- [ ] Boolean variables: `is`, `has`, `should` prefix

**Example - Consistent Naming:**
```typescript
// Constants
const MAX_RETRY_ATTEMPTS = 3;
const DEFAULT_TIMEOUT_MS = 5000;

// Types
interface UserRepository {
  findById(id: string): Promise<User | null>;
}

type RequestHandler<TRequest, TResponse> = (
  request: TRequest
) => Promise<TResponse>;

// Variables and functions
const userService = new UserService();
const isAuthenticated = checkAuth();
const hasPermission = checkPermission(user, 'admin');

// Class with private field
class DatabaseConnection {
  #pool: Pool | null = null;

  async connect(): Promise<void> {
    this.#pool = new Pool();
  }
}
```

### Code Organization
- [ ] Organize by feature, not by type
- [ ] Collocate related code
- [ ] Use absolute imports for cross-feature code
- [ ] Use relative imports within features
- [ ] Keep modules focused and cohesive

**Example - Feature-Based Organization:**
```
src/
├── features/
│   ├── users/
│   │   ├── user.service.ts
│   │   ├── user.controller.ts
│   │   ├── user.model.ts
│   │   ├── user.types.ts
│   │   └── user.validator.ts
│   ├── orders/
│   │   ├── order.service.ts
│   │   ├── order.controller.ts
│   │   ├── order.model.ts
│   │   └── order.types.ts
└── shared/
    ├── database/
    ├── auth/
    └── utils/
```

### Avoid Common Anti-Patterns
- [ ] Never use `any` type (use `unknown` instead)
- [ ] Never use `Function` type (define specific signatures)
- [ ] Don't overuse classes (use objects/functions when appropriate)
- [ ] Don't copy-paste type definitions (derive with utility types)
- [ ] Don't fight type inference (let TypeScript infer when possible)
- [ ] Don't throw errors for expected cases (use Result types)

See [typescript-anti-patterns.md](./typescript-anti-patterns.md) for detailed examples.

---

## References

- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)
- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)
- [Zod Documentation](https://zod.dev/)
- [TypeScript ESLint](https://typescript-eslint.io/)
- [TypeScript Style Guide by mkosir](https://mkosir.github.io/typescript-style-guide/)
- [Effective TypeScript Principles](https://www.dennisokeeffe.com/blog/2025-03-16-effective-typescript-principles-in-2025)
- [TypeScript Anti-Patterns](https://ducin.dev/typescript-anti-patterns)
