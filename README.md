# TypeScript Backend Expert - Code Review Skill

A comprehensive skill for reviewing TypeScript backend applications with a focus on Express and Fastify frameworks, emphasizing security (OWASP Top 10), performance optimization, type safety, and compliance standards (GDPR, SOC 2, HIPAA).

> **Inspired by**: This project was inspired by the excellent [typescript-code-review](https://github.com/Exploration-labs/typescript-code-review) skill, adapted specifically for backend development with Express and Fastify frameworks.

## Features

### 🔒 Security-First Approach
- **OWASP Top 10 2021** coverage with practical examples
- Input validation and sanitization patterns
- Authentication and authorization best practices
- SQL/NoSQL injection prevention
- XSS, CSRF, and SSRF protection
- Secure password storage and session management
- Rate limiting and DoS protection

### ⚡ Performance Optimization
- Database query optimization and N+1 prevention
- Connection pooling strategies
- Caching patterns (Redis, in-memory)
- Async operation optimization
- Event loop best practices
- Memory leak prevention
- Response streaming and compression

### 🎯 Type Safety
- Strict TypeScript configuration
- Advanced type patterns and generics
- Runtime validation with Zod/Joi
- Type guards and narrowing
- Avoiding `any` type
- Proper error handling types
- **NEW**: Anti-pattern detection (10 common mistakes)
- **NEW**: Modern patterns (8 advanced patterns)

### 📋 Compliance Standards
- **GDPR**: Data subject rights, consent management, data minimization
- **SOC 2**: Trust Services Criteria, audit logging
- **HIPAA**: PHI protection (if applicable)
- **PCI DSS**: Payment card data security (if applicable)
- Data retention and deletion policies
- Audit trail implementation

### 🚀 Framework-Specific Expertise

#### Express.js
- Middleware architecture and ordering
- Error handling patterns
- Route organization
- Authentication/authorization middleware
- Testing with Supertest

#### Fastify
- Schema-based validation and serialization
- Plugin architecture
- Hook system
- Type-safe route handlers
- Performance optimization

## Structure

```
typescript-backend-expert/
├── SKILL.md                           # Main skill instructions
├── README.md                          # This file
├── references/                        # Reference materials
│   ├── security-checklist.md          # OWASP Top 10 & security patterns
│   ├── performance-checklist.md       # Performance optimization guide
│   ├── compliance-checklist.md        # GDPR, SOC 2, HIPAA, PCI DSS
│   ├── type-safety-checklist.md       # TypeScript best practices
│   ├── typescript-anti-patterns.md    # Common anti-patterns to avoid
│   ├── advanced-typescript-patterns.md # Modern TypeScript patterns
│   ├── express-best-practices.md      # Express-specific patterns
│   └── fastify-best-practices.md      # Fastify-specific patterns
└── examples/                          # Code examples
    ├── security-examples.md           # Good vs bad security patterns (10 patterns)
    └── performance-examples.md        # Good vs bad performance patterns (11 patterns)
```


## Usage with Claude Code

This skill is designed to work with [Claude Code](https://claude.com/claude-code), Anthropic's AI coding assistant. It enhances Claude's ability to review TypeScript backend code with specialized knowledge of Express, Fastify, security, and compliance.

### Installation

1. **Place the skill in your Claude Code skills directory**:
   ```bash
   # Navigate to your Claude Code skills directory
   cd ~/.claude-code/skills/

   # Clone or copy this repository
   git clone https://github.com/robbanp/typescript-backend-expert.git
   ```

2. **The skill will be automatically available** when you use Claude Code in your TypeScript backend projects.

### How It Works

Claude Code automatically loads skills from your skills directory and activates them based on context. This skill activates when:

- You're working in a TypeScript project
- You request code reviews
- You ask about backend best practices
- You mention Express or Fastify
- You request security or performance analysis

### Using the Skill

Once installed, you can interact with Claude Code naturally:

**Code Review Request**:
```
"Review this Express route handler for security issues"
"Check this Fastify plugin for performance problems"
"Review my authentication middleware"
```

**Best Practices**:
```
"What's the best way to handle errors in Express?"
"Show me how to implement rate limiting in Fastify"
"How should I structure my TypeScript backend project?"
```

**Specific Analysis**:
```
"Check this code for OWASP Top 10 vulnerabilities"
"Review this for GDPR compliance"
"Analyze this database query for N+1 problems"
```

### What You Get

This skill provides comprehensive code reviews for TypeScript backend applications, focusing on:

1. **Security Analysis**: Identifies vulnerabilities based on OWASP Top 10
2. **Performance Review**: Detects bottlenecks and suggests optimizations
3. **Type Safety**: Ensures proper TypeScript usage and strict typing
4. **Compliance**: Validates adherence to regulatory requirements
5. **Best Practices**: Framework-specific patterns for Express/Fastify

### Review Severity Levels

Claude Code will categorize findings into four severity levels:

- 🔴 **Critical Issues**: Security vulnerabilities, data exposure, critical bugs that must be fixed immediately
- 🟡 **Important Improvements**: Performance issues, missing validations, maintainability concerns
- 🔵 **Suggestions**: Code organization, modern patterns, optional enhancements
- ✅ **Positive Observations**: Well-implemented patterns worth noting


## Checklists

### Security Checklist
- [ ] Input validation and sanitization
- [ ] SQL/NoSQL injection prevention
- [ ] Authentication and authorization
- [ ] XSS and CSRF protection
- [ ] Rate limiting
- [ ] Secure password storage
- [ ] Environment variables for secrets
- [ ] Security headers (Helmet.js)
- [ ] HTTPS enforcement
- [ ] Audit logging

### Performance Checklist
- [ ] Database query optimization
- [ ] Connection pooling
- [ ] N+1 query prevention
- [ ] Caching strategy
- [ ] Async operation optimization
- [ ] Response compression
- [ ] Streaming large responses
- [ ] Memory leak prevention
- [ ] Event loop monitoring

### Type Safety Checklist
- [ ] Strict TypeScript configuration
- [ ] No implicit `any`
- [ ] Proper type annotations
- [ ] Runtime validation (Zod, Joi)
- [ ] Type guards and narrowing
- [ ] Generic types where appropriate
- [ ] Typed request/response
- [ ] Error type handling

### Compliance Checklist
- [ ] Data retention policies
- [ ] User data export/deletion
- [ ] Consent management
- [ ] Audit logging
- [ ] Access controls
- [ ] Encryption at rest and in transit
- [ ] Privacy policy compliance
- [ ] Third-party data sharing controls

## Key Technologies Covered

### Frameworks
- Express.js 4.x
- Fastify 4.x

### Databases
- MongoDB (Mongoose)
- PostgreSQL (pg, TypeORM, Prisma)
- Redis (ioredis)

### Security
- Helmet.js
- bcrypt / argon2
- jsonwebtoken
- express-rate-limit / @fastify/rate-limit

### Validation
- Zod
- Joi
- class-validator

### Testing
- Jest
- Supertest
- @fastify/inject

### Tools
- TypeScript 5.x
- ESLint
- Prettier

## Examples Provided

### Security Examples (10 Patterns)
1. SQL/NoSQL injection prevention
2. IDOR (Insecure Direct Object Reference) protection
3. XSS prevention
4. Secure JWT implementation
5. Password hashing (bcrypt, argon2)
6. Rate limiting
7. Command injection prevention
8. Session management
9. Environment variables and secrets
10. SSRF protection

### Performance Examples (11 Patterns)
1. N+1 query resolution with DataLoader
2. Parallel vs sequential operations
3. Worker threads for CPU-intensive tasks
4. Memory leak prevention and cleanup
5. Database query optimization
6. Caching strategies (Redis, LRU)
7. Connection pooling
8. Response streaming
9. Response compression
10. Async operation optimization
11. Database index usage

### TypeScript Anti-Patterns (10 Common Mistakes)
1. Overusing `any` type
2. Overusing classes unnecessarily
3. Using `Function` type
4. Fighting type inference
5. Copy-pasting type definitions
6. Not using discriminated unions
7. Inheritance over composition
8. Not using `never` for exhaustive checks
9. Throwing errors everywhere
10. Not using const assertions

### Modern TypeScript Patterns (8 Advanced Patterns)
1. Schema-first development with Zod
2. Result type pattern for error handling
3. Dependency injection with interfaces
4. Discriminated unions for state management
5. Functional core, imperative shell
6. Builder pattern for complex objects
7. Type-safe event emitters
8. Generic repository pattern


## Example Review Output

When you ask Claude Code to review your code, you'll receive structured, actionable feedback:

```markdown
## TypeScript Backend Code Review

### Summary
Reviewing Express authentication middleware for security and type safety.

### Critical Issues 🔴

1. **SQL Injection Vulnerability** - auth.controller.ts:42
   - Problem: Using string concatenation for database query
   - Risk: Attacker could expose all user data
   - Fix: Use parameterized queries
   - Code: `db.query('SELECT * FROM users WHERE username = $1', [username])`
   - Reference: OWASP A03:2021 - Injection

2. **Missing Rate Limiting** - auth.routes.ts:15
   - Problem: Login endpoint has no rate limiting
   - Risk: Brute force attacks possible
   - Fix: Add express-rate-limit middleware
   - Reference: OWASP A04:2021 - Insecure Design

### Important Improvements 🟡

1. **N+1 Query Problem** - user.service.ts:67
   - Problem: Fetching users in loop (100 users = 101 queries)
   - Impact: Response time increases from 50ms to 2000ms
   - Fix: Use DataLoader or .populate()
   - Example: See /examples/performance-examples.md

### Suggestions 🔵

1. **Unnecessary Type Annotation** - user.controller.ts:23
   - TypeScript can infer the type here
   - Consider removing explicit annotation
   - Reference: /references/typescript-anti-patterns.md #4

### Positive Observations ✅

1. **Excellent Error Handling** - error.middleware.ts
   - Clean discriminated union pattern
   - No sensitive data in error responses
   - Proper logging with correlation IDs

### Recommended Actions
1. [URGENT] Fix SQL injection in auth.controller.ts
2. [HIGH] Add rate limiting to /api/auth/* endpoints
3. [MEDIUM] Optimize user service queries
```

### What Makes This Different

Unlike generic code reviews, this skill provides:

✅ **Context-Aware Analysis**: Understands Express vs Fastify patterns  
✅ **Security-First**: Checks all OWASP Top 10 vulnerabilities  
✅ **Compliance-Ready**: Validates GDPR, SOC 2, HIPAA requirements  
✅ **Performance-Focused**: Identifies N+1 queries, memory leaks, bottlenecks  
✅ **Type-Safety Expert**: Catches anti-patterns and suggests modern TypeScript patterns  
✅ **Actionable Feedback**: Every issue includes fix with code examples  
✅ **Standards-Referenced**: Links to OWASP, TypeScript, framework documentation  
✅ **Prioritized**: Clear severity levels help you focus on critical issues first

## References

### Security
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

### Performance
- [Node.js Performance Best Practices](https://nodejs.org/en/docs/guides/simple-profiling/)
- [Express Performance Best Practices](https://expressjs.com/en/advanced/best-practice-performance.html)
- [Fastify Benchmarks](https://www.fastify.io/benchmarks/)

### Compliance
- [GDPR Official Text](https://gdpr-info.eu/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)

### Frameworks
- [Express.js Documentation](https://expressjs.com/)
- [Fastify Documentation](https://www.fastify.io/)
- [TypeScript Documentation](https://www.typescriptlang.org/)

### TypeScript Best Practices
- [TypeScript Style Guide by mkosir](https://mkosir.github.io/typescript-style-guide/)
- [Effective TypeScript Principles 2025](https://www.dennisokeeffe.com/blog/2025-03-16-effective-typescript-principles-in-2025)
- [TypeScript Anti-Patterns](https://ducin.dev/typescript-anti-patterns)
- [Zod Documentation](https://zod.dev/)
- [neverthrow Library](https://github.com/supermacro/neverthrow)

## Acknowledgments

This project was inspired by the excellent [typescript-code-review](https://github.com/Exploration-labs/typescript-code-review) skill by Exploration Labs. We've adapted and expanded their approach specifically for backend development, focusing on Express and Fastify frameworks with additional emphasis on:

- Security (OWASP Top 10 2021)
- Performance optimization for backend APIs
- Compliance standards (GDPR, SOC 2, HIPAA)
- Modern TypeScript patterns and anti-patterns
- Production-ready backend architecture

Special thanks to the TypeScript, Node.js, Express, and Fastify communities for their extensive documentation and best practices.

## License

This skill is designed for use with Claude Code and follows best practices from the TypeScript, Node.js, Express, and Fastify communities.

## Contributing

To improve this skill:
1. Add new examples to the `examples/` directory
2. Update checklists in `references/` with latest security/performance patterns
3. Keep framework-specific guides current with latest versions
4. Add new compliance standards as needed

## Version

**Version**: 1.1.0  
**Last Updated**: 2025  
**TypeScript**: 5.x  
**Express**: 4.x  
**Fastify**: 4.x  
**OWASP Top 10**: 2021 Edition

### Changelog

#### v1.1.0 (2025)
- Added TypeScript anti-patterns reference (10 common mistakes)
- Added advanced TypeScript patterns (8 modern patterns)
- Enhanced type-safety checklist with modern best practices
- Added Result type pattern for error handling
- Added schema-first development patterns with Zod
- Added dependency injection patterns
- Added discriminated unions for state management
- Added functional core, imperative shell pattern
