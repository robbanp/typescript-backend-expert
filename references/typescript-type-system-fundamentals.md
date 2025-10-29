# TypeScript Type System Fundamentals

Deep dive into TypeScript's type system mechanics for building robust, type-safe backend applications.

---

## 1. Generics Deep Dive

### Basic Generic Constraints

```typescript
// Constraint with extends
function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
  return obj[key];
}

const user = { id: '123', name: 'Alice', age: 30 };
const name = getProperty(user, 'name'); // Type: string
// getProperty(user, 'invalid'); // Error: Argument of type '"invalid"' is not assignable
```

### Multiple Type Parameters

```typescript
// Function with multiple generic types
function merge<T, U>(obj1: T, obj2: U): T & U {
  return { ...obj1, ...obj2 };
}

const merged = merge({ id: 1 }, { name: 'Alice' });
// Type: { id: number } & { name: string }

// With constraints
function updateEntity<T extends { id: string }, U extends Partial<T>>(
  entity: T,
  updates: U
): T {
  return { ...entity, ...updates };
}
```

### Generic Defaults

```typescript
// Default type parameters
interface ApiResponse<T = unknown, E = Error> {
  data?: T;
  error?: E;
  status: number;
}

// Usage without specifying types
const response: ApiResponse = { status: 200 }; // T = unknown, E = Error

// Usage with one type
const userResponse: ApiResponse<User> = {
  data: user,
  status: 200
}; // E defaults to Error

// Usage with both types
const customResponse: ApiResponse<User, AppError> = {
  error: new NotFoundError('User', '123'),
  status: 404,
};
```

### Generic Inference

```typescript
// Let TypeScript infer generic types
function wrapInArray<T>(value: T): T[] {
  return [value];
}

const numbers = wrapInArray(42); // Type: number[]
const strings = wrapInArray('hello'); // Type: string[]

// Inference with constraints
function firstElement<T extends any[]>(arr: T): T[0] {
  return arr[0];
}

const first = firstElement([1, 2, 3]); // Type: number
const firstString = firstElement(['a', 'b']); // Type: string
```

### Generic Class Patterns

```typescript
// Generic service class
class CrudService<T extends { id: string }> {
  constructor(private repository: Repository<T>) {}

  async findById(id: string): Promise<T | null> {
    return this.repository.findById(id);
  }

  async findAll(filter?: Partial<T>): Promise<T[]> {
    return this.repository.findAll(filter);
  }

  async create(data: Omit<T, 'id'>): Promise<T> {
    return this.repository.create(data);
  }

  async update(id: string, data: Partial<T>): Promise<T | null> {
    return this.repository.update(id, data);
  }
}

// Usage
interface User {
  id: string;
  name: string;
  email: string;
}

const userService = new CrudService<User>(userRepository);
```

---

## 2. Conditional Types

### Basic Conditional Types

```typescript
// Simple conditional type
type IsString<T> = T extends string ? true : false;

type A = IsString<string>; // true
type B = IsString<number>; // false

// Nested conditions
type TypeName<T> = T extends string
  ? 'string'
  : T extends number
  ? 'number'
  : T extends boolean
  ? 'boolean'
  : T extends undefined
  ? 'undefined'
  : T extends Function
  ? 'function'
  : 'object';

type T1 = TypeName<string>; // 'string'
type T2 = TypeName<42>; // 'number'
type T3 = TypeName<() => void>; // 'function'
```

### Inferring Types with `infer`

```typescript
// Extract return type from function
type ReturnType<T> = T extends (...args: any[]) => infer R ? R : never;

function getUser(): Promise<User> {
  return Promise.resolve({ id: '1', name: 'Alice', email: 'alice@example.com' });
}

type UserReturnType = ReturnType<typeof getUser>; // Promise<User>

// Extract promise value type
type UnwrapPromise<T> = T extends Promise<infer U> ? U : T;

type User = UnwrapPromise<ReturnType<typeof getUser>>; // User

// Extract array element type
type ArrayElement<T> = T extends (infer U)[] ? U : T;

type NumberArray = number[];
type Num = ArrayElement<NumberArray>; // number
```

### Distributive Conditional Types

```typescript
// Distributive behavior with unions
type ToArray<T> = T extends any ? T[] : never;

type StrOrNum = string | number;
type StrOrNumArray = ToArray<StrOrNum>; // string[] | number[]

// Non-distributive (using tuple)
type ToArrayNonDist<T> = [T] extends [any] ? T[] : never;

type Combined = ToArrayNonDist<StrOrNum>; // (string | number)[]

// Exclude null/undefined
type NonNullable<T> = T extends null | undefined ? never : T;

type MaybeString = string | null | undefined;
type DefinitelyString = NonNullable<MaybeString>; // string
```

### Practical Conditional Types for APIs

```typescript
// Extract required vs optional keys
type RequiredKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? never : K;
}[keyof T];

type OptionalKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? K : never;
}[keyof T];

interface UserInput {
  id: string;
  name: string;
  email?: string;
  age?: number;
}

type Required = RequiredKeys<UserInput>; // 'id' | 'name'
type Optional = OptionalKeys<UserInput>; // 'email' | 'age'

// Create validation schema type
type ValidationSchema<T> = {
  [K in RequiredKeys<T>]: Validator<T[K]>;
} & {
  [K in OptionalKeys<T>]?: Validator<T[K]>;
};
```

---

## 3. Mapped Types

### Basic Mapped Types

```typescript
// Create readonly version
type Readonly<T> = {
  readonly [K in keyof T]: T[K];
};

// Create optional version
type Partial<T> = {
  [K in keyof T]?: T[K];
};

// Create required version
type Required<T> = {
  [K in keyof T]-?: T[K]; // -? removes optional modifier
};

// Remove readonly
type Mutable<T> = {
  -readonly [K in keyof T]: T[K]; // -readonly removes readonly modifier
};
```

### Key Remapping with `as`

```typescript
// Add prefix to keys
type Prefixed<T, Prefix extends string> = {
  [K in keyof T as `${Prefix}${string & K}`]: T[K];
};

interface User {
  id: string;
  name: string;
  email: string;
}

type PrefixedUser = Prefixed<User, 'user_'>;
// { user_id: string; user_name: string; user_email: string }

// Create getter methods
type Getters<T> = {
  [K in keyof T as `get${Capitalize<string & K>}`]: () => T[K];
};

type UserGetters = Getters<User>;
// { getId: () => string; getName: () => string; getEmail: () => string }

// Filter out specific types
type RemoveNullable<T> = {
  [K in keyof T as T[K] extends null | undefined ? never : K]: T[K];
};

interface Data {
  id: string;
  name: string | null;
  age: number | undefined;
  active: boolean;
}

type CleanData = RemoveNullable<Data>;
// { id: string; active: boolean }
```

### Practical Mapped Types for Backend

```typescript
// Convert API response to database model
type ApiToDb<T> = {
  [K in keyof T as K extends 'createdAt' | 'updatedAt'
    ? `${K}_timestamp`
    : K]: T[K];
};

interface ApiUser {
  id: string;
  name: string;
  createdAt: Date;
  updatedAt: Date;
}

type DbUser = ApiToDb<ApiUser>;
// { id: string; name: string; createdAt_timestamp: Date; updatedAt_timestamp: Date }

// Create update type (partial but require at least one field)
type AtLeastOne<T> = {
  [K in keyof T]: Pick<T, K> & Partial<Omit<T, K>>;
}[keyof T];

type UpdateUser = AtLeastOne<Pick<User, 'name' | 'email'>>;
// Must have at least name or email, can have both

// Create environment variables type from config
type EnvVars<T> = {
  [K in keyof T as `${Uppercase<string & K>}`]: T[K] extends string
    ? string
    : T[K] extends number
    ? string
    : string;
};

interface Config {
  port: number;
  host: string;
  dbUrl: string;
}

type Environment = EnvVars<Config>;
// { PORT: string; HOST: string; DB_URL: string }
```

---

## 4. Template Literal Types

### Basic Template Literals

```typescript
// Combine string types
type Protocol = 'http' | 'https';
type Domain = 'example.com' | 'api.example.com';

type URL = `${Protocol}://${Domain}`;
// 'http://example.com' | 'http://api.example.com' |
// 'https://example.com' | 'https://api.example.com'

// Create CSS units
type Unit = 'px' | 'em' | 'rem' | '%';
type CSSValue<T extends number> = `${T}${Unit}`;

type Width = CSSValue<100>; // '100px' | '100em' | '100rem' | '100%'
```

### Type-Safe Express/Fastify Routes

```typescript
// HTTP methods
type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

// Route patterns
type RoutePattern = `/${string}`;

// Combine method and route
type Route<M extends HTTPMethod = HTTPMethod, P extends RoutePattern = RoutePattern> =
  `${M} ${P}`;

// Extract path parameters
type ExtractRouteParams<T extends string> =
  T extends `${infer _Start}:${infer Param}/${infer Rest}`
    ? { [K in Param | keyof ExtractRouteParams<Rest>]: string }
    : T extends `${infer _Start}:${infer Param}`
    ? { [K in Param]: string }
    : {};

type UserRoute = '/users/:userId/posts/:postId';
type Params = ExtractRouteParams<UserRoute>;
// { userId: string; postId: string }

// Type-safe route builder
class TypedRouter {
  get<Path extends RoutePattern>(
    path: Path,
    handler: (params: ExtractRouteParams<Path>) => void
  ) {
    // Implementation
  }
}

const router = new TypedRouter();

router.get('/users/:userId', (params) => {
  // params is typed as { userId: string }
  console.log(params.userId);
});
```

### API Endpoint Types

```typescript
// Create REST endpoint types
type Resource = 'users' | 'posts' | 'comments';
type Action = 'list' | 'get' | 'create' | 'update' | 'delete';

type Endpoint<R extends Resource, A extends Action> =
  A extends 'list' | 'create'
    ? `/api/${R}`
    : `/api/${R}/:id`;

type UserEndpoints = {
  list: Endpoint<'users', 'list'>; // '/api/users'
  get: Endpoint<'users', 'get'>; // '/api/users/:id'
  create: Endpoint<'users', 'create'>; // '/api/users'
  update: Endpoint<'users', 'update'>; // '/api/users/:id'
  delete: Endpoint<'users', 'delete'>; // '/api/users/:id'
};

// Event naming convention
type EventName<Entity extends string, Action extends string> =
  `${Entity}:${Action}`;

type UserEvents =
  | EventName<'user', 'created'>
  | EventName<'user', 'updated'>
  | EventName<'user', 'deleted'>;
// 'user:created' | 'user:updated' | 'user:deleted'
```

### Query String Types

```typescript
// Convert object to query string type
type QueryString<T> = {
  [K in keyof T]: T[K] extends string | number | boolean
    ? `${string & K}=${T[K]}`
    : never;
}[keyof T];

interface SearchParams {
  page: number;
  limit: number;
  sort: 'asc' | 'desc';
}

type QueryParams = QueryString<SearchParams>;
// 'page=number' | 'limit=number' | 'sort=asc' | 'sort=desc'

// Extract query parameters from URL
type ExtractQueryParams<T extends string> =
  T extends `${infer _Path}?${infer Query}`
    ? Query extends `${infer Key}=${infer Value}&${infer Rest}`
      ? { [K in Key]: string } & ExtractQueryParams<`?${Rest}`>
      : Query extends `${infer Key}=${infer Value}`
      ? { [K in Key]: string }
      : {}
    : {};

type URLWithQuery = '/api/users?page=1&limit=10&sort=desc';
type QueryParamsFromURL = ExtractQueryParams<URLWithQuery>;
// { page: string; limit: string; sort: string }
```

---

## 5. Built-in Utility Types Reference

### Object Utilities

```typescript
// Partial - make all properties optional
type Partial<T> = {
  [P in keyof T]?: T[P];
};

interface User {
  id: string;
  name: string;
  email: string;
}

type PartialUser = Partial<User>;
// { id?: string; name?: string; email?: string }

// Required - make all properties required
type Required<T> = {
  [P in keyof T]-?: T[P];
};

// Readonly - make all properties readonly
type Readonly<T> = {
  readonly [P in keyof T]: T[P];
};

// Pick - select specific properties
type Pick<T, K extends keyof T> = {
  [P in K]: T[P];
};

type UserIdentity = Pick<User, 'id' | 'email'>;
// { id: string; email: string }

// Omit - remove specific properties
type Omit<T, K extends keyof any> = Pick<T, Exclude<keyof T, K>>;

type UserWithoutId = Omit<User, 'id'>;
// { name: string; email: string }

// Record - create object type with specific keys and values
type Record<K extends keyof any, T> = {
  [P in K]: T;
};

type UserRoles = Record<string, 'admin' | 'user' | 'guest'>;
// { [key: string]: 'admin' | 'user' | 'guest' }

type HTTPStatusMessages = Record<number, string>;
// { [key: number]: string }
```

### Union Utilities

```typescript
// Exclude - remove types from union
type Exclude<T, U> = T extends U ? never : T;

type Numbers = 1 | 2 | 3 | 4 | 5;
type LowNumbers = Exclude<Numbers, 4 | 5>; // 1 | 2 | 3

// Extract - extract types from union
type Extract<T, U> = T extends U ? T : never;

type HighNumbers = Extract<Numbers, 4 | 5>; // 4 | 5

// NonNullable - remove null and undefined
type NonNullable<T> = T extends null | undefined ? never : T;

type MaybeString = string | null | undefined;
type DefinitelyString = NonNullable<MaybeString>; // string
```

### Function Utilities

```typescript
// Parameters - extract function parameters as tuple
type Parameters<T extends (...args: any) => any> =
  T extends (...args: infer P) => any ? P : never;

function createUser(name: string, email: string, age: number) {
  return { name, email, age };
}

type CreateUserParams = Parameters<typeof createUser>;
// [name: string, email: string, age: number]

// ReturnType - extract function return type
type ReturnType<T extends (...args: any) => any> =
  T extends (...args: any) => infer R ? R : any;

type User = ReturnType<typeof createUser>;
// { name: string; email: string; age: number }

// ConstructorParameters - extract constructor parameters
type ConstructorParameters<T extends abstract new (...args: any) => any> =
  T extends abstract new (...args: infer P) => any ? P : never;

class UserService {
  constructor(repo: UserRepository, logger: Logger) {}
}

type ServiceParams = ConstructorParameters<typeof UserService>;
// [repo: UserRepository, logger: Logger]

// InstanceType - extract instance type from constructor
type InstanceType<T extends abstract new (...args: any) => any> =
  T extends abstract new (...args: any) => infer R ? R : any;

type ServiceInstance = InstanceType<typeof UserService>;
// UserService
```

### Async Utilities

```typescript
// Awaited - unwrap Promise type
type Awaited<T> = T extends Promise<infer U> ? U : T;

async function fetchUser(): Promise<User> {
  return { id: '1', name: 'Alice', email: 'alice@example.com' };
}

type UserData = Awaited<ReturnType<typeof fetchUser>>;
// User (not Promise<User>)

// Nested promises
type NestedPromise = Promise<Promise<string>>;
type Unwrapped = Awaited<NestedPromise>; // string
```

---

## 6. Deep Recursive Utilities

### Deep Readonly

```typescript
type DeepReadonly<T> = {
  readonly [K in keyof T]: T[K] extends object
    ? T[K] extends Function
      ? T[K]
      : DeepReadonly<T[K]>
    : T[K];
};

interface UserWithPosts {
  id: string;
  profile: {
    name: string;
    settings: {
      theme: string;
      notifications: boolean;
    };
  };
  posts: Array<{ id: string; title: string }>;
}

type ImmutableUser = DeepReadonly<UserWithPosts>;
// All nested properties are readonly
```

### Deep Partial

```typescript
type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object
    ? T[K] extends Function
      ? T[K]
      : DeepPartial<T[K]>
    : T[K];
};

type PartialUpdate = DeepPartial<UserWithPosts>;
// All nested properties are optional
```

### Deep Required

```typescript
type DeepRequired<T> = {
  [K in keyof T]-?: T[K] extends object
    ? T[K] extends Function
      ? T[K]
      : DeepRequired<T[K]>
    : T[K];
};

interface OptionalConfig {
  database?: {
    host?: string;
    port?: number;
    credentials?: {
      username?: string;
      password?: string;
    };
  };
}

type RequiredConfig = DeepRequired<OptionalConfig>;
// All nested properties are required
```

### Path Type Utilities

```typescript
// Get all paths in nested object
type Paths<T, D extends number = 10> = [D] extends [never]
  ? never
  : T extends object
  ? {
      [K in keyof T]-?: K extends string | number
        ? `${K}` | Join<K, Paths<T[K], Prev[D]>>
        : never;
    }[keyof T]
  : '';

type Join<K, P> = K extends string | number
  ? P extends string | number
    ? `${K}${'' extends P ? '' : '.'}${P}`
    : never
  : never;

type Prev = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

interface NestedData {
  user: {
    profile: {
      name: string;
      age: number;
    };
    settings: {
      theme: string;
    };
  };
}

type AllPaths = Paths<NestedData>;
// 'user' | 'user.profile' | 'user.profile.name' | 'user.profile.age' |
// 'user.settings' | 'user.settings.theme'

// Get value at path
type PathValue<T, P extends string> = P extends `${infer K}.${infer Rest}`
  ? K extends keyof T
    ? PathValue<T[K], Rest>
    : never
  : P extends keyof T
  ? T[P]
  : never;

type UserName = PathValue<NestedData, 'user.profile.name'>; // string
type Theme = PathValue<NestedData, 'user.settings.theme'>; // string
```

---

## 7. Type-Safe API Client

### Complete Type-Safe Client

```typescript
// Define API schema
interface APISchema {
  '/users': {
    GET: {
      query: { page?: number; limit?: number };
      response: { users: User[]; total: number };
    };
    POST: {
      body: { name: string; email: string };
      response: User;
    };
  };
  '/users/:id': {
    GET: {
      params: { id: string };
      response: User;
    };
    PUT: {
      params: { id: string };
      body: Partial<User>;
      response: User;
    };
    DELETE: {
      params: { id: string };
      response: { success: boolean };
    };
  };
  '/posts': {
    GET: {
      query: { userId?: string };
      response: Post[];
    };
  };
}

// Extract endpoint paths
type Endpoint = keyof APISchema;

// Extract methods for endpoint
type Methods<E extends Endpoint> = keyof APISchema[E] & HTTPMethod;

// Extract request config for method
type RequestConfig<
  E extends Endpoint,
  M extends Methods<E>
> = APISchema[E][M] extends { params: infer P }
  ? APISchema[E][M] extends { query: infer Q }
    ? APISchema[E][M] extends { body: infer B }
      ? { params: P; query: Q; body: B }
      : { params: P; query: Q }
    : APISchema[E][M] extends { body: infer B }
    ? { params: P; body: B }
    : { params: P }
  : APISchema[E][M] extends { query: infer Q }
  ? APISchema[E][M] extends { body: infer B }
    ? { query: Q; body: B }
    : { query: Q }
  : APISchema[E][M] extends { body: infer B }
  ? { body: B }
  : {};

// Extract response type
type ResponseType<
  E extends Endpoint,
  M extends Methods<E>
> = APISchema[E][M] extends { response: infer R } ? R : never;

// Type-safe API client
class APIClient<Schema extends Record<string, any>> {
  constructor(private baseURL: string) {}

  async request<
    E extends keyof Schema,
    M extends keyof Schema[E] & string
  >(
    endpoint: E,
    method: M,
    config?: RequestConfig<E, M>
  ): Promise<ResponseType<E, M>> {
    const url = this.buildURL(endpoint as string, config);
    const response = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: 'body' in (config || {})
        ? JSON.stringify((config as any).body)
        : undefined,
    });

    return response.json();
  }

  private buildURL(endpoint: string, config: any): string {
    let url = `${this.baseURL}${endpoint}`;

    // Replace params
    if (config?.params) {
      Object.entries(config.params).forEach(([key, value]) => {
        url = url.replace(`:${key}`, String(value));
      });
    }

    // Add query string
    if (config?.query) {
      const params = new URLSearchParams(
        Object.entries(config.query)
          .filter(([, value]) => value !== undefined)
          .map(([key, value]) => [key, String(value)])
      );
      url += `?${params}`;
    }

    return url;
  }
}

// Usage - fully type-safe!
const client = new APIClient<APISchema>('https://api.example.com');

// GET with query params
const users = await client.request('/users', 'GET', {
  query: { page: 1, limit: 10 }, // Typed!
});
// users is typed as { users: User[]; total: number }

// POST with body
const newUser = await client.request('/users', 'POST', {
  body: { name: 'Alice', email: 'alice@example.com' }, // Typed!
});
// newUser is typed as User

// GET with path params
const user = await client.request('/users/:id', 'GET', {
  params: { id: '123' }, // Typed!
});
// user is typed as User

// PUT with params and body
const updated = await client.request('/users/:id', 'PUT', {
  params: { id: '123' },
  body: { name: 'Bob' }, // Partial<User> typed!
});
// updated is typed as User
```

### Microservice Communication

```typescript
// Define service interfaces
interface UserService {
  '/api/users/:id': {
    GET: { params: { id: string }; response: User };
  };
  '/api/users': {
    POST: { body: CreateUserInput; response: User };
  };
}

interface OrderService {
  '/api/orders': {
    GET: { query: { userId: string }; response: Order[] };
    POST: { body: CreateOrderInput; response: Order };
  };
}

// Service registry
interface Services {
  users: UserService;
  orders: OrderService;
}

// Type-safe service client
class ServiceClient<S extends Record<string, any>> {
  constructor(
    private serviceName: keyof S,
    private baseURL: string
  ) {}

  async call<
    E extends keyof S[keyof S],
    M extends keyof S[keyof S][E] & string
  >(
    endpoint: E,
    method: M,
    config?: RequestConfig<E, M>
  ): Promise<ResponseType<E, M>> {
    // Implementation similar to APIClient
    return {} as any;
  }
}

// Usage
const userService = new ServiceClient<Services>('users', 'http://users-svc:3000');
const orderService = new ServiceClient<Services>('orders', 'http://orders-svc:3001');

// Fully typed service calls
const user = await userService.call('/api/users/:id', 'GET', {
  params: { id: '123' },
});

const orders = await orderService.call('/api/orders', 'GET', {
  query: { userId: user.id },
});
```

---

## Practical Backend Examples

### Type-Safe Database Queries

```typescript
// Query builder with type safety
type Operator = 'eq' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'like';

type WhereCondition<T> = {
  [K in keyof T]?: {
    [O in Operator]?: O extends 'in'
      ? T[K][]
      : O extends 'like'
      ? string
      : T[K];
  };
};

interface User {
  id: string;
  name: string;
  age: number;
  email: string;
}

// Usage
const query: WhereCondition<User> = {
  age: { gte: 18, lt: 65 },
  name: { like: '%john%' },
  email: { in: ['john@example.com', 'jane@example.com'] },
};
```

### Type-Safe Validation

```typescript
// Convert schema to validator type
type Validator<T> = (value: unknown) => value is T;

type ValidationRules<T> = {
  [K in keyof T]: {
    required?: boolean;
    validator?: Validator<T[K]>;
    transform?: (value: any) => T[K];
  };
};

interface UserInput {
  name: string;
  email: string;
  age: number;
}

const userValidation: ValidationRules<UserInput> = {
  name: {
    required: true,
    validator: (val): val is string => typeof val === 'string' && val.length > 0,
  },
  email: {
    required: true,
    validator: (val): val is string => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(val)),
  },
  age: {
    required: true,
    transform: (val) => parseInt(String(val), 10),
    validator: (val): val is number => Number.isInteger(val) && val >= 0,
  },
};
```

---

## References

- [TypeScript Handbook - Generics](https://www.typescriptlang.org/docs/handbook/2/generics.html)
- [TypeScript Handbook - Conditional Types](https://www.typescriptlang.org/docs/handbook/2/conditional-types.html)
- [TypeScript Handbook - Mapped Types](https://www.typescriptlang.org/docs/handbook/2/mapped-types.html)
- [TypeScript Handbook - Template Literal Types](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html)
- [TypeScript Handbook - Utility Types](https://www.typescriptlang.org/docs/handbook/utility-types.html)
- [Type Challenges](https://github.com/type-challenges/type-challenges) - Practice advanced TypeScript types
