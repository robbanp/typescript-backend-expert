# Compliance Checklist for TypeScript Backend Applications

## General Data Protection Regulation (GDPR)

### Data Subject Rights

#### Right to Access (Art. 15)
- [ ] API endpoint for data subject access requests
- [ ] Ability to export all personal data in machine-readable format
- [ ] Response within 30 days implementation
- [ ] Identity verification before data disclosure

**Example - Data Export Endpoint:**
```typescript
interface DataExportRequest {
  userId: string;
  includeProcessingHistory: boolean;
}

app.get('/api/gdpr/export-data', authenticate, async (req, res) => {
  const userId = req.user.id;

  // Verify identity (e.g., email confirmation, 2FA)
  await verifyIdentity(userId, req.body.verificationToken);

  const personalData = {
    profile: await User.findById(userId).select('-password'),
    orders: await Order.find({ userId }),
    preferences: await Preferences.findOne({ userId }),
    activityLog: await ActivityLog.find({ userId }).limit(1000),
    consents: await Consent.find({ userId }),
  };

  // Log the access request
  await AuditLog.create({
    userId,
    action: 'DATA_EXPORT_REQUEST',
    timestamp: new Date(),
    ip: req.ip,
  });

  res.json({
    requestId: generateRequestId(),
    exportedAt: new Date().toISOString(),
    data: personalData,
  });
});
```

#### Right to Rectification (Art. 16)
- [ ] User profile update endpoints
- [ ] Data validation for updates
- [ ] Audit trail for corrections
- [ ] Notification to third parties if data shared

#### Right to Erasure / "Right to be Forgotten" (Art. 17)
- [ ] Account deletion endpoint
- [ ] Data anonymization strategy
- [ ] Retention period validation
- [ ] Cascading deletion or anonymization
- [ ] Legal hold check before deletion

**Example - Data Erasure:**
```typescript
interface DeletionRequest {
  userId: string;
  reason: 'user_request' | 'data_retention' | 'legal_requirement';
  retainForLegal?: boolean;
}

async function eraseUserData(request: DeletionRequest): Promise<void> {
  const { userId, reason } = request;

  // Check if legal hold applies
  const legalHold = await checkLegalHold(userId);
  if (legalHold) {
    throw new Error('Cannot delete user data: legal hold in place');
  }

  // Start transaction
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Anonymize instead of delete for audit purposes
    await User.findByIdAndUpdate(userId, {
      email: `deleted_${userId}@anonymized.local`,
      firstName: 'Deleted',
      lastName: 'User',
      phone: null,
      address: null,
      dateOfBirth: null,
      deletedAt: new Date(),
      deletionReason: reason,
    }, { session });

    // Delete or anonymize related data
    await Order.updateMany(
      { userId },
      {
        $set: {
          userId: 'ANONYMIZED',
          shippingAddress: null,
          billingAddress: null,
        }
      },
      { session }
    );

    // Delete sensitive data
    await Session.deleteMany({ userId }, { session });
    await PaymentMethod.deleteMany({ userId }, { session });

    // Keep anonymized audit logs for compliance
    await AuditLog.updateMany(
      { userId },
      { $set: { userId: 'ANONYMIZED' } },
      { session }
    );

    // Log deletion
    await AuditLog.create([{
      action: 'USER_DATA_ERASURE',
      userId: 'SYSTEM',
      targetUserId: userId,
      reason,
      timestamp: new Date(),
    }], { session });

    await session.commitTransaction();
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}
```

#### Right to Data Portability (Art. 20)
- [ ] Structured, machine-readable export (JSON, CSV)
- [ ] Industry-standard formats
- [ ] Direct transfer to another controller (if feasible)

#### Right to Object / Opt-Out (Art. 21)
- [ ] Marketing preference management
- [ ] Processing objection handling
- [ ] Automated decision-making opt-out

### Data Processing Principles

#### Lawfulness, Fairness, Transparency (Art. 5)
- [ ] Legal basis documented for each processing activity
- [ ] Privacy policy available
- [ ] Clear consent mechanisms
- [ ] Transparent data collection

**Example - Consent Management:**
```typescript
interface ConsentRecord {
  userId: string;
  purpose: 'marketing' | 'analytics' | 'personalization' | 'essential';
  granted: boolean;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  version: string; // Privacy policy version
}

async function recordConsent(record: ConsentRecord): Promise<void> {
  await Consent.create(record);

  // Update user preferences
  await User.findByIdAndUpdate(record.userId, {
    $set: {
      [`consents.${record.purpose}`]: {
        granted: record.granted,
        timestamp: record.timestamp,
      }
    }
  });
}

// Middleware to check consent
function requireConsent(purpose: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const consent = await Consent.findOne({
      userId: req.user.id,
      purpose,
      granted: true,
    }).sort({ timestamp: -1 });

    if (!consent) {
      return res.status(403).json({
        error: 'Consent required',
        purpose,
        consentUrl: '/api/consent',
      });
    }

    next();
  };
}
```

#### Purpose Limitation (Art. 5)
- [ ] Data processing limited to stated purposes
- [ ] New purposes require new consent
- [ ] Purpose documented in privacy policy

#### Data Minimization (Art. 5)
- [ ] Collect only necessary data
- [ ] Regular review of collected data fields
- [ ] Justify each data field collected

#### Accuracy (Art. 5)
- [ ] Data validation on input
- [ ] Regular data quality checks
- [ ] User ability to update information

#### Storage Limitation (Art. 5)
- [ ] Data retention policies defined
- [ ] Automated data deletion after retention period
- [ ] Archival strategy for legal requirements

**Example - Data Retention:**
```typescript
interface RetentionPolicy {
  dataType: string;
  retentionPeriodDays: number;
  archiveBeforeDelete: boolean;
  legalBasis: string;
}

const RETENTION_POLICIES: RetentionPolicy[] = [
  {
    dataType: 'user_activity_logs',
    retentionPeriodDays: 90,
    archiveBeforeDelete: false,
    legalBasis: 'Legitimate interest - security monitoring'
  },
  {
    dataType: 'order_records',
    retentionPeriodDays: 2555, // 7 years for tax purposes
    archiveBeforeDelete: true,
    legalBasis: 'Legal obligation - tax law'
  },
  {
    dataType: 'marketing_preferences',
    retentionPeriodDays: 730, // 2 years
    archiveBeforeDelete: false,
    legalBasis: 'Consent - marketing communications'
  },
];

// Scheduled job to enforce retention
async function enforceRetentionPolicies(): Promise<void> {
  for (const policy of RETENTION_POLICIES) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - policy.retentionPeriodDays);

    if (policy.dataType === 'user_activity_logs') {
      const deleted = await ActivityLog.deleteMany({
        timestamp: { $lt: cutoffDate }
      });

      logger.info('Retention policy enforced', {
        dataType: policy.dataType,
        deletedCount: deleted.deletedCount,
        cutoffDate,
      });
    }
  }
}
```

#### Integrity and Confidentiality (Art. 5)
- [ ] Encryption at rest
- [ ] Encryption in transit (TLS)
- [ ] Access controls
- [ ] Regular security assessments

### Accountability (Art. 5)

#### Records of Processing Activities (Art. 30)
- [ ] Documentation of all processing activities
- [ ] Purpose, categories, recipients documented
- [ ] Data flow maps
- [ ] Regular updates to documentation

#### Data Protection Impact Assessment (DPIA) (Art. 35)
- [ ] DPIA for high-risk processing
- [ ] Risk mitigation measures
- [ ] Regular DPIA reviews

#### Data Breach Notification (Art. 33-34)
- [ ] Breach detection mechanisms
- [ ] 72-hour notification procedure
- [ ] Incident response plan
- [ ] Breach logging

**Example - Breach Detection:**
```typescript
interface SecurityIncident {
  type: 'unauthorized_access' | 'data_leak' | 'ransomware' | 'other';
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedUsers: string[];
  detectedAt: Date;
  description: string;
  containmentActions: string[];
}

async function reportSecurityIncident(incident: SecurityIncident): Promise<void> {
  // Log incident
  await SecurityIncidentLog.create(incident);

  // Determine if breach notification required
  const requiresNotification =
    incident.severity === 'high' ||
    incident.severity === 'critical' ||
    incident.affectedUsers.length > 100;

  if (requiresNotification) {
    // Alert DPO
    await alertDataProtectionOfficer(incident);

    // Start 72-hour countdown
    await scheduleRegulatoryNotification(incident, 72);
  }

  // Notify affected users if high risk
  if (incident.severity === 'critical') {
    await notifyAffectedUsers(incident);
  }
}
```

---

## SOC 2 (System and Organization Controls 2)

### Trust Services Criteria

#### Security
- [ ] Access control policies implemented
- [ ] Multi-factor authentication
- [ ] Encryption of sensitive data
- [ ] Network security (firewalls, IDS/IPS)
- [ ] Vulnerability management
- [ ] Security awareness training

**Example - Access Control:**
```typescript
enum Role {
  ADMIN = 'admin',
  USER = 'user',
  AUDITOR = 'auditor',
  SUPPORT = 'support',
}

enum Permission {
  READ_USER_DATA = 'read:user_data',
  WRITE_USER_DATA = 'write:user_data',
  DELETE_USER_DATA = 'delete:user_data',
  ACCESS_AUDIT_LOGS = 'access:audit_logs',
}

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  [Role.ADMIN]: [
    Permission.READ_USER_DATA,
    Permission.WRITE_USER_DATA,
    Permission.DELETE_USER_DATA,
    Permission.ACCESS_AUDIT_LOGS,
  ],
  [Role.USER]: [Permission.READ_USER_DATA, Permission.WRITE_USER_DATA],
  [Role.AUDITOR]: [Permission.READ_USER_DATA, Permission.ACCESS_AUDIT_LOGS],
  [Role.SUPPORT]: [Permission.READ_USER_DATA],
};

function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user.role as Role;
    const allowedPermissions = ROLE_PERMISSIONS[userRole] || [];

    if (!allowedPermissions.includes(permission)) {
      // Log unauthorized access attempt
      logger.warn('Unauthorized access attempt', {
        userId: req.user.id,
        role: userRole,
        requiredPermission: permission,
        endpoint: req.path,
      });

      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}
```

#### Availability
- [ ] System monitoring and alerting
- [ ] Disaster recovery plan
- [ ] Business continuity planning
- [ ] Backup and recovery procedures
- [ ] SLA commitments

**Example - Health Check Endpoint:**
```typescript
interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: {
    database: 'up' | 'down';
    redis: 'up' | 'down';
    external_api: 'up' | 'down';
  };
  uptime: number;
}

app.get('/health', async (req, res) => {
  const checks = await Promise.allSettled([
    checkDatabase(),
    checkRedis(),
    checkExternalAPI(),
  ]);

  const result: HealthCheckResult = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: checks[0].status === 'fulfilled' ? 'up' : 'down',
      redis: checks[1].status === 'fulfilled' ? 'up' : 'down',
      external_api: checks[2].status === 'fulfilled' ? 'up' : 'down',
    },
    uptime: process.uptime(),
  };

  const anyDown = Object.values(result.services).some(s => s === 'down');
  if (anyDown) {
    result.status = 'degraded';
    res.status(503);
  }

  res.json(result);
});
```

#### Processing Integrity
- [ ] Data validation controls
- [ ] Error handling and logging
- [ ] Transaction integrity
- [ ] Quality assurance procedures

#### Confidentiality
- [ ] Data classification
- [ ] Access restrictions based on classification
- [ ] Non-disclosure agreements
- [ ] Secure disposal procedures

#### Privacy
- [ ] Privacy notice provided
- [ ] Consent mechanisms
- [ ] Data subject rights supported
- [ ] Third-party data sharing controls

### Audit Logging

- [ ] Comprehensive audit trail
- [ ] Log integrity protection
- [ ] Log retention policy
- [ ] Regular log review
- [ ] Tamper-evident logging

**Example - Comprehensive Audit Logging:**
```typescript
interface AuditLogEntry {
  timestamp: Date;
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  outcome: 'success' | 'failure';
  ipAddress: string;
  userAgent: string;
  requestId: string;
  changes?: {
    before: any;
    after: any;
  };
}

class AuditLogger {
  async log(entry: AuditLogEntry): Promise<void> {
    // Add checksum for integrity
    const checksum = this.generateChecksum(entry);

    await AuditLog.create({
      ...entry,
      checksum,
    });

    // Also send to external SIEM if critical
    if (this.isCriticalAction(entry.action)) {
      await this.sendToSIEM(entry);
    }
  }

  private generateChecksum(entry: AuditLogEntry): string {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(entry))
      .digest('hex');
  }

  private isCriticalAction(action: string): boolean {
    const criticalActions = [
      'USER_DELETED',
      'PERMISSION_CHANGED',
      'DATA_EXPORTED',
      'ADMIN_ACCESS',
    ];
    return criticalActions.includes(action);
  }
}

// Middleware to audit all requests
app.use((req, res, next) => {
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;

    auditLogger.log({
      timestamp: new Date(),
      userId: req.user?.id,
      action: `${req.method} ${req.path}`,
      resource: req.path,
      outcome: res.statusCode < 400 ? 'success' : 'failure',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      requestId: req.headers['x-request-id'] as string,
    });
  });

  next();
});
```

---

## HIPAA (Health Insurance Portability and Accountability Act)

*Note: Only if handling Protected Health Information (PHI)*

### Administrative Safeguards
- [ ] Security management process
- [ ] Assigned security responsibility
- [ ] Workforce security procedures
- [ ] Information access management
- [ ] Security awareness training
- [ ] Security incident procedures
- [ ] Contingency planning
- [ ] Business associate agreements

### Physical Safeguards
- [ ] Facility access controls
- [ ] Workstation use policies
- [ ] Workstation security
- [ ] Device and media controls

### Technical Safeguards
- [ ] Access control (unique user IDs, emergency access)
- [ ] Audit controls
- [ ] Integrity controls
- [ ] Person or entity authentication
- [ ] Transmission security

**Example - PHI Access Logging:**
```typescript
interface PHIAccessLog {
  accessedBy: string;
  patientId: string;
  purpose: 'treatment' | 'payment' | 'operations' | 'other';
  dataAccessed: string[];
  timestamp: Date;
  ipAddress: string;
}

async function accessPatientRecord(
  userId: string,
  patientId: string,
  purpose: string
): Promise<PatientRecord> {
  // Log PHI access
  await PHIAccessLog.create({
    accessedBy: userId,
    patientId,
    purpose,
    dataAccessed: ['demographics', 'medical_history'],
    timestamp: new Date(),
    ipAddress: getCurrentIP(),
  });

  // Verify access authorization
  const authorized = await checkPHIAccess(userId, patientId, purpose);
  if (!authorized) {
    throw new Error('Unauthorized PHI access');
  }

  return await PatientRecord.findById(patientId);
}
```

---

## PCI DSS (Payment Card Industry Data Security Standard)

*Note: Only if handling payment card data*

### Key Requirements
- [ ] Never store full magnetic stripe, CVV2, or PIN data
- [ ] Encryption of cardholder data at rest
- [ ] Encryption during transmission
- [ ] Tokenization where possible
- [ ] Use payment gateway instead of storing card data
- [ ] Regular security testing

**Example - Payment Processing:**
```typescript
// ✅ Good - Use payment gateway (Stripe example)
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

async function processPayment(amount: number, paymentMethodId: string) {
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100, // Convert to cents
      currency: 'usd',
      payment_method: paymentMethodId,
      confirm: true,
    });

    // Store only payment reference, not card data
    await Order.create({
      amount,
      stripePaymentIntentId: paymentIntent.id,
      status: 'paid',
    });

    return { success: true, paymentIntentId: paymentIntent.id };
  } catch (error) {
    logger.error('Payment processing failed', { error });
    throw new Error('Payment failed');
  }
}

// ❌ Bad - Never store raw card data
// const cardData = {
//   cardNumber: req.body.cardNumber, // NEVER DO THIS
//   cvv: req.body.cvv, // NEVER DO THIS
// };
```

---

## ISO 27001 Information Security Management

### Annex A Controls
- [ ] Information security policies
- [ ] Organization of information security
- [ ] Human resource security
- [ ] Asset management
- [ ] Access control
- [ ] Cryptography
- [ ] Physical and environmental security
- [ ] Operations security
- [ ] Communications security
- [ ] System acquisition, development and maintenance
- [ ] Supplier relationships
- [ ] Information security incident management
- [ ] Business continuity management
- [ ] Compliance

---

## General Compliance Best Practices

### Data Classification
```typescript
enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
}

interface ClassifiedData {
  classification: DataClassification;
  data: any;
  owner: string;
  retentionPeriod: number; // days
}
```

### Regular Compliance Audits
- [ ] Automated compliance checking in CI/CD
- [ ] Regular penetration testing
- [ ] Code reviews for compliance
- [ ] Third-party security audits

### Documentation
- [ ] Privacy policy
- [ ] Terms of service
- [ ] Data processing agreements
- [ ] Security documentation
- [ ] Incident response procedures

---

## References

- [GDPR Official Text](https://gdpr-info.eu/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)
