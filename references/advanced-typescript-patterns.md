# Advanced TypeScript Patterns for Backend Development

Modern patterns and principles for building robust, type-safe backend applications in TypeScript.

---

## 1. Schema-First Development with Zod

Define your data schemas first, then derive TypeScript types from them. This ensures runtime validation matches compile-time types.

### Pattern: Single Source of Truth
```typescript
import { z } from 'zod';

// Schema is the source of truth
const UserSchema = z.object({
  id: z.string().uuid(),
  username: z.string().min(3).max(30),
  email: z.string().email(),
  role: z.enum(['user', 'admin', 'moderator']),
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date(),
});

// Derive TypeScript types
type User = z.infer<typeof UserSchema>;

// Create variations using Zod methods
const CreateUserSchema = UserSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
type CreateUserInput = z.infer<typeof CreateUserSchema>;

const UpdateUserSchema = UserSchema.partial().pick({
  username: true,
  email: true,
  role: true,
  isActive: true,
});
type UpdateUserInput = z.infer<typeof UpdateUserSchema>;

const UserResponseSchema = UserSchema.omit({ password: true });
type UserResponse = z.infer<typeof UserResponseSchema>;
```

### Pattern: Boundary Validation
```typescript
import { Request, Response, NextFunction } from 'express';

// Validation middleware factory
function validateBody<T extends z.ZodType>(schema: T) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors.map(e => ({
            path: e.path.join('.'),
            message: e.message,
          })),
        });
      }
      next(error);
    }
  };
}

// Usage
app.post('/users', validateBody(CreateUserSchema), async (req, res) => {
  // req.body is now typed and validated!
  const user = await createUser(req.body);
  res.json(user);
});
```

### Pattern: Transform and Coerce
```typescript
// Handle different data representations
const TimestampSchema = z.object({
  // Coerce string to Date
  createdAt: z.coerce.date(),
  // Transform string to number
  expiresIn: z.string().transform(val => parseInt(val, 10)),
});

// API might send: { createdAt: "2025-01-01T00:00:00Z", expiresIn: "3600" }
// After parsing: { createdAt: Date, expiresIn: 3600 }
```

---

## 2. Result Type Pattern for Error Handling

Replace throw-based error handling with explicit Result types for expected errors.

### Pattern: Basic Result Type
```typescript
type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

// Helper constructors
function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

// Usage
async function findUser(id: string): Promise<Result<User, string>> {
  try {
    const user = await User.findById(id);

    if (!user) {
      return err('User not found');
    }

    return ok(user);
  } catch (error) {
    return err('Database error');
  }
}

// Explicit error handling
const result = await findUser('123');
if (result.ok) {
  console.log(result.value.name);
} else {
  console.error(result.error);
}
```

### Pattern: Using neverthrow Library
```typescript
import { Result, ok, err, ResultAsync } from 'neverthrow';

// Service methods return Result types
class UserService {
  async getUser(id: string): Promise<Result<User, AppError>> {
    try {
      const user = await User.findById(id);
      return user ? ok(user) : err(new NotFoundError('User', id));
    } catch (error) {
      return err(new DatabaseError(error));
    }
  }

  async updateUser(
    id: string,
    data: UpdateUserInput
  ): Promise<Result<User, AppError>> {
    return ResultAsync.fromPromise(
      User.findByIdAndUpdate(id, data, { new: true }),
      error => new DatabaseError(error)
    )
      .andThen(user =>
        user ? ok(user) : err(new NotFoundError('User', id))
      );
  }
}

// Chain operations
const result = await userService
  .getUser('123')
  .andThen(user => userService.updateUser(user.id, { username: 'newname' }))
  .map(user => ({ id: user.id, username: user.username }))
  .mapErr(error => ({
    message: error.message,
    statusCode: error.statusCode,
  }));

if (result.isOk()) {
  res.json(result.value);
} else {
  res.status(result.error.statusCode).json({ error: result.error.message });
}
```

### Pattern: Categorized Errors
```typescript
// Base error with metadata
abstract class AppError extends Error {
  abstract readonly statusCode: number;
  abstract readonly code: string;
  readonly timestamp: Date;

  constructor(message: string) {
    super(message);
    this.timestamp = new Date();
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

class ValidationError extends AppError {
  readonly statusCode = 400;
  readonly code = 'VALIDATION_ERROR';

  constructor(
    message: string,
    public readonly fields: Record<string, string>
  ) {
    super(message);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

class NotFoundError extends AppError {
  readonly statusCode = 404;
  readonly code = 'NOT_FOUND';

  constructor(
    public readonly resource: string,
    public readonly id: string
  ) {
    super(`${resource} with id ${id} not found`);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

class UnauthorizedError extends AppError {
  readonly statusCode = 401;
  readonly code = 'UNAUTHORIZED';

  constructor(message: string = 'Unauthorized') {
    super(message);
    Object.setPrototypeOf(this, UnauthorizedError.prototype);
  }
}

class DatabaseError extends AppError {
  readonly statusCode = 500;
  readonly code = 'DATABASE_ERROR';

  constructor(public readonly originalError: unknown) {
    super('Database operation failed');
    Object.setPrototypeOf(this, DatabaseError.prototype);
  }
}

// Type-safe error handling
function handleError(error: AppError, res: Response): void {
  res.status(error.statusCode).json({
    error: {
      code: error.code,
      message: error.message,
      timestamp: error.timestamp.toISOString(),
      ...(error instanceof ValidationError && { fields: error.fields }),
      ...(error instanceof NotFoundError && {
        resource: error.resource,
        id: error.id,
      }),
    },
  });
}
```

---

## 3. Dependency Injection Pattern

### Pattern: Constructor Injection with Interfaces
```typescript
// Define interfaces for dependencies
interface ILogger {
  info(message: string, meta?: object): void;
  error(message: string, error: Error, meta?: object): void;
  warn(message: string, meta?: object): void;
}

interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: CreateUserInput): Promise<User>;
  update(id: string, data: UpdateUserInput): Promise<User | null>;
  delete(id: string): Promise<boolean>;
}

interface IEmailService {
  sendWelcomeEmail(user: User): Promise<void>;
  sendPasswordResetEmail(user: User, token: string): Promise<void>;
}

// Service with injected dependencies
class UserService {
  constructor(
    private readonly logger: ILogger,
    private readonly userRepo: IUserRepository,
    private readonly emailService: IEmailService
  ) {}

  async createUser(data: CreateUserInput): Promise<Result<User, AppError>> {
    this.logger.info('Creating user', { email: data.email });

    // Check if user exists
    const existing = await this.userRepo.findByEmail(data.email);
    if (existing) {
      return err(
        new ValidationError('Email already in use', { email: 'Already exists' })
      );
    }

    // Create user
    const user = await this.userRepo.create(data);

    // Send welcome email (async, don't wait)
    this.emailService.sendWelcomeEmail(user).catch(error => {
      this.logger.error('Failed to send welcome email', error, {
        userId: user.id,
      });
    });

    this.logger.info('User created', { userId: user.id });
    return ok(user);
  }
}

// Easy to test with mocks
describe('UserService', () => {
  it('should create user', async () => {
    const mockLogger = { info: jest.fn(), error: jest.fn(), warn: jest.fn() };
    const mockRepo = {
      findByEmail: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue(mockUser),
    } as any;
    const mockEmail = {
      sendWelcomeEmail: jest.fn().mockResolvedValue(undefined),
    } as any;

    const service = new UserService(mockLogger, mockRepo, mockEmail);

    const result = await service.createUser(createUserInput);

    expect(result.ok).toBe(true);
    expect(mockRepo.create).toHaveBeenCalledWith(createUserInput);
  });
});
```

### Pattern: Factory Pattern for DI Container
```typescript
// Simple DI container
class Container {
  private services = new Map<string, any>();

  register<T>(key: string, factory: () => T): void {
    this.services.set(key, factory);
  }

  resolve<T>(key: string): T {
    const factory = this.services.get(key);
    if (!factory) {
      throw new Error(`Service ${key} not found`);
    }
    return factory();
  }
}

// Setup container
const container = new Container();

container.register('logger', () => new WinstonLogger());
container.register('database', () => new MongoDatabase());
container.register(
  'userRepo',
  () => new UserRepository(container.resolve('database'))
);
container.register('emailService', () => new SendGridEmailService());
container.register(
  'userService',
  () =>
    new UserService(
      container.resolve('logger'),
      container.resolve('userRepo'),
      container.resolve('emailService')
    )
);

// Resolve service
const userService = container.resolve<UserService>('userService');
```

---

## 4. Discriminated Unions for State Management

### Pattern: Request State
```typescript
type RequestState<T> =
  | { status: 'idle' }
  | { status: 'loading'; startedAt: Date }
  | { status: 'success'; data: T; loadedAt: Date }
  | { status: 'error'; error: string; failedAt: Date };

function processRequest<T>(state: RequestState<T>): void {
  switch (state.status) {
    case 'idle':
      console.log('Request not started');
      break;
    case 'loading':
      console.log(`Loading since ${state.startedAt}`);
      break;
    case 'success':
      console.log(`Loaded at ${state.loadedAt}:`, state.data);
      break;
    case 'error':
      console.error(`Failed at ${state.failedAt}:`, state.error);
      break;
  }
}
```

### Pattern: Database Operation Result
```typescript
type DbOperation<T> =
  | { type: 'insert'; result: T; rowsAffected: 1 }
  | { type: 'update'; result: T; rowsAffected: number }
  | { type: 'delete'; rowsAffected: number }
  | { type: 'select'; results: T[]; totalCount: number };

function handleDbOperation<T>(operation: DbOperation<T>): void {
  switch (operation.type) {
    case 'insert':
      console.log('Inserted:', operation.result);
      break;
    case 'update':
      console.log(`Updated ${operation.rowsAffected} rows`, operation.result);
      break;
    case 'delete':
      console.log(`Deleted ${operation.rowsAffected} rows`);
      break;
    case 'select':
      console.log(
        `Found ${operation.results.length} of ${operation.totalCount}`
      );
      break;
  }
}
```

### Pattern: Payment Status
```typescript
type PaymentStatus =
  | { status: 'pending'; createdAt: Date }
  | { status: 'processing'; processor: string; transactionId: string }
  | { status: 'completed'; completedAt: Date; transactionId: string }
  | { status: 'failed'; reason: string; failedAt: Date }
  | { status: 'refunded'; refundedAt: Date; amount: number };

interface Payment {
  id: string;
  amount: number;
  currency: string;
  paymentStatus: PaymentStatus;
}

function canRefund(payment: Payment): boolean {
  return payment.paymentStatus.status === 'completed';
}

function getTransactionId(payment: Payment): string | null {
  const { paymentStatus } = payment;

  if (
    paymentStatus.status === 'processing' ||
    paymentStatus.status === 'completed'
  ) {
    return paymentStatus.transactionId;
  }

  return null;
}
```

---

## 5. Functional Core, Imperative Shell

Keep business logic pure and side effects at the boundaries.

### Pattern: Pure Business Logic
```typescript
// Pure functions - no side effects
type OrderItem = {
  productId: string;
  quantity: number;
  price: number;
};

type Order = {
  items: OrderItem[];
  subtotal: number;
  tax: number;
  discount: number;
  total: number;
};

// Pure calculation functions
function calculateSubtotal(items: OrderItem[]): number {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}

function calculateTax(subtotal: number, taxRate: number): number {
  return subtotal * taxRate;
}

function applyDiscount(
  subtotal: number,
  discountCode: string | null
): number {
  const discounts: Record<string, number> = {
    SAVE10: 0.1,
    SAVE20: 0.2,
  };

  const rate = discountCode ? discounts[discountCode] || 0 : 0;
  return subtotal * rate;
}

function calculateTotal(
  subtotal: number,
  tax: number,
  discount: number
): number {
  return subtotal + tax - discount;
}

// Pure composition
function buildOrder(
  items: OrderItem[],
  taxRate: number,
  discountCode: string | null
): Order {
  const subtotal = calculateSubtotal(items);
  const tax = calculateTax(subtotal, taxRate);
  const discount = applyDiscount(subtotal, discountCode);
  const total = calculateTotal(subtotal, tax, discount);

  return {
    items,
    subtotal,
    tax,
    discount,
    total,
  };
}

// Imperative shell - handles side effects
class OrderService {
  constructor(
    private readonly orderRepo: IOrderRepository,
    private readonly inventoryService: IInventoryService,
    private readonly logger: ILogger
  ) {}

  async createOrder(
    userId: string,
    items: OrderItem[],
    discountCode: string | null
  ): Promise<Result<Order, AppError>> {
    this.logger.info('Creating order', { userId, itemCount: items.length });

    // Check inventory (side effect)
    const inventoryCheck = await this.inventoryService.checkAvailability(
      items
    );
    if (!inventoryCheck.available) {
      return err(new ValidationError('Items not available', {}));
    }

    // Pure business logic
    const order = buildOrder(items, 0.08, discountCode);

    // Save to database (side effect)
    try {
      const savedOrder = await this.orderRepo.create({
        userId,
        ...order,
      });

      // Update inventory (side effect)
      await this.inventoryService.reserveItems(items);

      this.logger.info('Order created', { orderId: savedOrder.id });

      return ok(savedOrder);
    } catch (error) {
      this.logger.error('Failed to create order', error as Error, { userId });
      return err(new DatabaseError(error));
    }
  }
}
```

---

## 6. Builder Pattern for Complex Objects

### Pattern: Fluent Builder
```typescript
class QueryBuilder<T> {
  private filters: Array<(item: T) => boolean> = [];
  private sortFn?: (a: T, b: T) => number;
  private limitValue?: number;
  private offsetValue: number = 0;

  where(predicate: (item: T) => boolean): this {
    this.filters.push(predicate);
    return this;
  }

  sortBy(compareFn: (a: T, b: T) => number): this {
    this.sortFn = compareFn;
    return this;
  }

  limit(count: number): this {
    this.limitValue = count;
    return this;
  }

  offset(count: number): this {
    this.offsetValue = count;
    return this;
  }

  execute(data: T[]): T[] {
    let result = data;

    // Apply filters
    for (const filter of this.filters) {
      result = result.filter(filter);
    }

    // Apply sorting
    if (this.sortFn) {
      result = result.sort(this.sortFn);
    }

    // Apply pagination
    if (this.offsetValue > 0) {
      result = result.slice(this.offsetValue);
    }

    if (this.limitValue !== undefined) {
      result = result.slice(0, this.limitValue);
    }

    return result;
  }
}

// Usage
const query = new QueryBuilder<User>()
  .where(user => user.isActive)
  .where(user => user.role === 'admin')
  .sortBy((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
  .limit(10)
  .offset(20);

const results = query.execute(allUsers);
```

---

## 7. Type-Safe Event Emitter

### Pattern: Strongly-Typed Events
```typescript
// Define event types
type EventMap = {
  'user.created': { userId: string; email: string };
  'user.updated': { userId: string; changes: Partial<User> };
  'user.deleted': { userId: string };
  'order.created': { orderId: string; userId: string; total: number };
  'order.completed': { orderId: string };
};

class TypedEventEmitter<TEvents extends Record<string, any>> {
  private listeners = new Map<keyof TEvents, Set<Function>>();

  on<K extends keyof TEvents>(
    event: K,
    handler: (data: TEvents[K]) => void | Promise<void>
  ): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }

    this.listeners.get(event)!.add(handler);

    // Return unsubscribe function
    return () => {
      this.listeners.get(event)?.delete(handler);
    };
  }

  async emit<K extends keyof TEvents>(event: K, data: TEvents[K]): Promise<void> {
    const handlers = this.listeners.get(event);

    if (!handlers) return;

    await Promise.all(
      Array.from(handlers).map(handler => Promise.resolve(handler(data)))
    );
  }

  removeAllListeners(event?: keyof TEvents): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }
}

// Usage
const events = new TypedEventEmitter<EventMap>();

// Type-safe subscription
events.on('user.created', async data => {
  console.log(`User ${data.userId} created with email ${data.email}`);
  // data is correctly typed!
});

// Type-safe emission
await events.emit('user.created', {
  userId: '123',
  email: 'user@example.com',
  // TypeScript will error if properties are missing or wrong type
});
```

---

## 8. Repository Pattern with Generic Base

### Pattern: Generic Repository
```typescript
interface BaseEntity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}

interface Repository<T extends BaseEntity> {
  findById(id: string): Promise<T | null>;
  findAll(filter?: Partial<T>): Promise<T[]>;
  create(data: Omit<T, keyof BaseEntity>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T | null>;
  delete(id: string): Promise<boolean>;
}

// Concrete implementation
class MongoRepository<T extends BaseEntity> implements Repository<T> {
  constructor(private model: Model<T>) {}

  async findById(id: string): Promise<T | null> {
    return this.model.findById(id).lean().exec();
  }

  async findAll(filter: Partial<T> = {}): Promise<T[]> {
    return this.model.find(filter as any).lean().exec();
  }

  async create(data: Omit<T, keyof BaseEntity>): Promise<T> {
    const doc = await this.model.create(data);
    return doc.toObject();
  }

  async update(id: string, data: Partial<T>): Promise<T | null> {
    return this.model
      .findByIdAndUpdate(id, data, { new: true })
      .lean()
      .exec();
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.model.findByIdAndDelete(id).exec();
    return result !== null;
  }
}

// Usage with specific types
interface User extends BaseEntity {
  username: string;
  email: string;
  role: string;
}

const userRepository = new MongoRepository<User>(UserModel);
const user = await userRepository.findById('123'); // Type: User | null
```

---

## References

- [Effective TypeScript Principles](https://www.dennisokeeffe.com/blog/2025-03-16-effective-typescript-principles-in-2025)
- [TypeScript Style Guide](https://mkosir.github.io/typescript-style-guide/)
- [Zod Documentation](https://zod.dev/)
- [neverthrow Documentation](https://github.com/supermacro/neverthrow)
