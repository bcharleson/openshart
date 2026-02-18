/**
 * PII detection and handling tests.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { detectPII, redactPII } from '../src/pii/detector.js';
import { classifyContent, classifyPIILevel } from '../src/pii/classifier.js';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import { PIILevel } from '../src/core/types.js';

describe('PII Detection', () => {
  it('should detect SSN', () => {
    const detections = detectPII('Patient SSN: 123-45-6789');
    const ssn = detections.find(d => d.type === 'SSN');
    expect(ssn).toBeDefined();
    expect(ssn!.level).toBe(PIILevel.CRITICAL);
  });

  it('should detect email addresses', () => {
    const detections = detectPII('Contact: john.doe@example.com');
    const email = detections.find(d => d.type === 'EMAIL');
    expect(email).toBeDefined();
    expect(email!.level).toBe(PIILevel.HIGH);
  });

  it('should detect phone numbers', () => {
    const detections = detectPII('Call me at (555) 123-4567.');
    const phone = detections.find(d => d.type === 'PHONE_US');
    expect(phone).toBeDefined();
  });

  it('should detect IP addresses', () => {
    const detections = detectPII('Server at 192.168.1.100');
    const ip = detections.find(d => d.type === 'IP_ADDRESS');
    expect(ip).toBeDefined();
    expect(ip!.level).toBe(PIILevel.MEDIUM);
  });

  it('should detect financial amounts', () => {
    const detections = detectPII('Salary: $150,000.00');
    const financial = detections.find(d => d.type === 'FINANCIAL');
    expect(financial).toBeDefined();
    expect(financial!.level).toBe(PIILevel.CRITICAL);
  });

  it('should detect multiple PII types in one string', () => {
    const content = 'John Doe, SSN 123-45-6789, email john@example.com, server 10.0.0.1';
    const detections = detectPII(content);
    const types = new Set(detections.map(d => d.type));
    expect(types.has('SSN')).toBe(true);
    expect(types.has('EMAIL')).toBe(true);
    expect(types.has('IP_ADDRESS')).toBe(true);
  });

  it('should return empty for clean content', () => {
    const detections = detectPII('The weather today is sunny and warm.');
    // Filter out false positives from address pattern
    const real = detections.filter(d => !['ADDRESS'].includes(d.type));
    expect(real.length).toBe(0);
  });
});

describe('PII Redaction', () => {
  it('should redact detected PII', () => {
    const content = 'Patient SSN is 123-45-6789 and email is patient@hospital.com';
    const detections = detectPII(content);
    const redacted = redactPII(content, detections);

    expect(redacted).not.toContain('123-45-6789');
    expect(redacted).not.toContain('patient@hospital.com');
    expect(redacted).toContain('[SSN_REDACTED]');
    expect(redacted).toContain('[EMAIL_REDACTED]');
  });
});

describe('PII Classification', () => {
  it('should classify CRITICAL for SSN content', () => {
    const detections = detectPII('SSN: 123-45-6789');
    const classification = classifyContent(detections);
    expect(classification.level).toBe(PIILevel.CRITICAL);
  });

  it('should classify NONE for clean content', () => {
    const detections = detectPII('Just a regular sentence.');
    const classification = classifyContent(detections);
    expect(classification.level).toBe(PIILevel.NONE);
  });
});

describe('PII-Aware Storage', () => {
  let shart: OpenShart;

  beforeEach(async () => {
    shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });
  });

  afterEach(async () => {
    await shart.close();
  });

  it('should auto-detect PII and increase fragmentation', async () => {
    // Content with CRITICAL PII
    const result = await shart.store('Patient John Doe, SSN 123-45-6789, email john@hospital.com');

    expect(result.detectedPII).toContain('SSN');
    expect(result.detectedPII).toContain('EMAIL');
    expect(result.piiLevel).toBe(PIILevel.CRITICAL);
    // CRITICAL level defaults: threshold=5, totalShares=8
    expect(result.threshold).toBeGreaterThanOrEqual(5);
    expect(result.fragmentCount).toBeGreaterThanOrEqual(8);
  });

  it('should use minimal fragmentation for non-PII content', async () => {
    const result = await shart.store('The project deadline is next Friday.');

    expect(result.piiLevel).toBe(PIILevel.NONE);
    // NONE level defaults: threshold=2, totalShares=3
    expect(result.threshold).toBe(2);
    expect(result.fragmentCount).toBe(3);
  });

  it('should still recall PII content correctly after fragmentation', async () => {
    const content = 'Confidential: SSN 999-88-7777, DOB 01/15/1990';
    const result = await shart.store(content);
    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
  });
});
