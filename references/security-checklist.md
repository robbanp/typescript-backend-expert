# Security Checklist for TypeScript Backend Applications

## OWASP Top 10 2021 Coverage

### A01:2021 - Broken Access Control

#### Authorization Checks
- [ ] All protected routes have authentication middleware
- [ ] Authorization checks verify user permissions before operations
- [ ] No reliance on client-side access control
- [ ] Deny access by default
- [ ] CORS properly configured (not `*` in production)
- [ ] Rate limiting on sensitive endpoints

#### Insecure Direct Object References (IDOR)
- [ ] Object IDs validated against user permissions
- [ ] No predictable IDs exposed (use UUIDs or encrypted IDs)
- [ ] Database queries filter by user ownership
- [ ] Multi-tenant data properly isolated

**Example - Bad:**
```typescript
// Vulnerable to IDOR
app.get('/api/orders/:id', async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  res.json(order);
});
```

**Example - Good:**
```typescript
// Protected against IDOR
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.orders.findOne({
    id: req.params.id,
    userId: req.user.id // Verify ownership
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

---

### A02:2021 - Cryptographic Failures

#### Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] TLS/HTTPS enforced for all endpoints
- [ ] No hardcoded secrets or credentials
- [ ] Environment variables used for secrets
- [ ] Secrets management solution (Vault, AWS Secrets Manager)
- [ ] Secure random values (crypto.randomBytes, not Math.random)

#### Password Security
- [ ] Strong password hashing (bcrypt, argon2, scrypt)
- [ ] Minimum password complexity requirements
- [ ] Salted hashes (automatic with bcrypt/argon2)
- [ ] No passwords in logs or error messages

#### Sensitive Data Handling
- [ ] PII minimization
- [ ] Sensitive data not in URLs or logs
- [ ] Proper key rotation procedures
- [ ] Secure deletion of sensitive data

**Example - Bad:**
```typescript
// Weak password storage
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**Example - Good:**
```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(password, SALT_ROUNDS);
```

---

### A03:2021 - Injection

#### SQL/NoSQL Injection
- [ ] Parameterized queries or ORM used
- [ ] No string concatenation in queries
- [ ] Input validation before database operations
- [ ] Proper escaping of special characters
- [ ] Principle of least privilege for database users

**Example - Bad (SQL Injection):**
```typescript
// Vulnerable to SQL injection
const query = `SELECT * FROM users WHERE username = '${username}'`;
const users = await db.query(query);
```

**Example - Good:**
```typescript
// Protected with parameterized query
const query = 'SELECT * FROM users WHERE username = $1';
const users = await db.query(query, [username]);
```

**Example - Bad (NoSQL Injection - MongoDB):**
```typescript
// Vulnerable to NoSQL injection
const user = await User.findOne({ username: req.body.username });
```

**Example - Good:**
```typescript
// Input validation prevents injection
const { username } = req.body;
if (typeof username !== 'string' || !/^[a-zA-Z0-9_]+$/.test(username)) {
  return res.status(400).json({ error: 'Invalid username' });
}
const user = await User.findOne({ username });
```

#### Command Injection
- [ ] Avoid shell execution where possible
- [ ] If shell needed, validate and sanitize all inputs
- [ ] Use safe APIs (child_process.spawn with array args)
- [ ] Never pass user input directly to eval() or similar

#### Other Injection Types
- [ ] LDAP injection prevention
- [ ] XPath injection prevention
- [ ] XML injection prevention
- [ ] Template injection prevention

---

### A04:2021 - Insecure Design

#### Security by Design
- [ ] Threat modeling performed
- [ ] Security requirements defined
- [ ] Rate limiting on all public endpoints
- [ ] Circuit breakers for external services
- [ ] Input validation at system boundaries
- [ ] Defense in depth strategy

#### Rate Limiting & DoS Protection
- [ ] Rate limiting middleware (express-rate-limit, fastify-rate-limit)
- [ ] Different limits for different endpoints
- [ ] Request size limits enforced
- [ ] Timeout configurations
- [ ] Connection limits

**Example - Express Rate Limiting:**
```typescript
import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 requests for sensitive endpoints
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', strictLimiter);
```

---

### A05:2021 - Security Misconfiguration

#### Configuration Security
- [ ] No default credentials
- [ ] Minimal error messages in production
- [ ] Security headers configured (Helmet.js)
- [ ] Unnecessary features disabled
- [ ] Directory listing disabled
- [ ] Development tools not in production
- [ ] HTTPS redirect enforced
- [ ] Cookie security flags (httpOnly, secure, sameSite)

**Example - Security Headers (Express):**
```typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
}));
```

**Example - Fastify Security:**
```typescript
import helmet from '@fastify/helmet';

await fastify.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
    },
  },
});
```

#### Error Handling
- [ ] Generic error messages to clients
- [ ] Detailed errors only in logs
- [ ] No stack traces in production responses
- [ ] No sensitive data in error messages

---

### A06:2021 - Vulnerable and Outdated Components

#### Dependency Management
- [ ] Regular dependency updates
- [ ] `npm audit` or `yarn audit` in CI/CD
- [ ] Automated vulnerability scanning (Snyk, Dependabot)
- [ ] No known CVEs in dependencies
- [ ] Minimal dependency footprint
- [ ] Pinned versions in package.json

**CI/CD Security Check:**
```bash
# In CI pipeline
npm audit --audit-level=high
npm outdated
```

---

### A07:2021 - Identification and Authentication Failures

#### Authentication
- [ ] Strong password requirements enforced
- [ ] Multi-factor authentication available
- [ ] Account lockout after failed attempts
- [ ] Secure session management
- [ ] JWT with proper expiration and validation
- [ ] Refresh token rotation
- [ ] No credentials in URLs

#### Session Management
- [ ] Secure session storage (Redis recommended)
- [ ] Session timeout configured
- [ ] Session regeneration after login
- [ ] Proper logout functionality
- [ ] CSRF protection for session-based auth

**Example - JWT Best Practices:**
```typescript
import jwt from 'jsonwebtoken';

interface JWTPayload {
  userId: string;
  role: string;
}

// Token generation
function generateTokens(userId: string, role: string) {
  const accessToken = jwt.sign(
    { userId, role } as JWTPayload,
    process.env.JWT_SECRET!,
    { expiresIn: '15m', issuer: 'myapp', audience: 'myapp-users' }
  );

  const refreshToken = jwt.sign(
    { userId, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET!,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

// Token validation
function verifyToken(token: string): JWTPayload {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    issuer: 'myapp',
    audience: 'myapp-users'
  }) as JWTPayload;
}
```

---

### A08:2021 - Software and Data Integrity Failures

#### Integrity Verification
- [ ] Package integrity checks (package-lock.json, yarn.lock)
- [ ] Signed releases/artifacts
- [ ] CI/CD pipeline security
- [ ] No unsigned third-party code
- [ ] Subresource Integrity (SRI) for CDN assets
- [ ] Input validation for updates/plugins

#### Deserialization
- [ ] Validate data before deserialization
- [ ] Avoid deserializing untrusted data
- [ ] Use safe JSON parsing
- [ ] No eval() or Function() constructor with user input

---

### A09:2021 - Security Logging and Monitoring Failures

#### Logging
- [ ] Audit logs for authentication events
- [ ] Audit logs for authorization failures
- [ ] Audit logs for input validation failures
- [ ] Centralized logging solution
- [ ] Log correlation IDs for request tracing
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Structured logging (JSON format)

#### Monitoring
- [ ] Security event alerting
- [ ] Failed authentication alerts
- [ ] Suspicious activity detection
- [ ] Log retention policy
- [ ] Regular log review

**Example - Structured Logging:**
```typescript
import winston from 'winston';

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Security event logging
function logSecurityEvent(event: string, details: object, userId?: string) {
  logger.warn('Security Event', {
    event,
    userId,
    timestamp: new Date().toISOString(),
    ...details
  });
}

// Usage
logSecurityEvent('failed_login', {
  username: sanitizeUsername(username),
  ip: req.ip,
  attemptCount: 3
});
```

---

### A10:2021 - Server-Side Request Forgery (SSRF)

#### URL Validation
- [ ] Whitelist of allowed domains/IPs
- [ ] No access to internal IPs (127.0.0.1, 10.x.x.x, 192.168.x.x)
- [ ] URL parsing and validation
- [ ] No cloud metadata endpoint access
- [ ] DNS rebinding protection

**Example - SSRF Prevention:**
```typescript
import { URL } from 'url';

const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];
const INTERNAL_IPS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^169\.254\./ // AWS metadata
];

function isUrlSafe(urlString: string): boolean {
  try {
    const url = new URL(urlString);

    // Check protocol
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }

    // Check against allowed domains
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      return false;
    }

    // Check for internal IPs
    for (const pattern of INTERNAL_IPS) {
      if (pattern.test(url.hostname)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

// Usage
app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;

  if (!isUrlSafe(url)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const response = await fetch(url);
  // ... handle response
});
```

---

## Additional Security Checks

### Input Validation
- [ ] Validation library used (joi, zod, yup, class-validator)
- [ ] All inputs validated at boundaries
- [ ] Type coercion handled safely
- [ ] File upload validation (type, size, content)
- [ ] Request size limits

### CSRF Protection
- [ ] CSRF tokens for state-changing operations
- [ ] SameSite cookie attribute
- [ ] Double-submit cookie pattern (if applicable)

### Content Security
- [ ] Content-Type validation
- [ ] File upload restrictions
- [ ] Image processing security (ImageMagick vulnerabilities)
- [ ] PDF processing security

### API Security
- [ ] API versioning strategy
- [ ] API key rotation capability
- [ ] Webhook signature verification
- [ ] GraphQL query depth limiting (if applicable)

---

## Security Testing

### Automated Testing
- [ ] Security unit tests
- [ ] Integration tests for auth/authz
- [ ] Dependency vulnerability scans
- [ ] SAST tools integrated

### Manual Testing
- [ ] Penetration testing performed
- [ ] Security code review
- [ ] Threat modeling
- [ ] Red team exercises

---

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
