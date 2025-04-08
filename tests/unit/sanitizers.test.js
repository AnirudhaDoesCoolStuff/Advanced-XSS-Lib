// tests/unit/sanitizers.test.js
// Sample unit tests for sanitizers
// In a real implementation, these would be runnable with Jest

// Test basic sanitizer
describe('Basic Sanitizer', () => {
  const { basicSanitize } = require('../../src/sanitizers/basicSanitizer');

  test('should remove script tags', () => {
    const input = '<p>Hello</p><script>alert("XSS")</script>';
    const expected = '<p>Hello</p>';
    expect(basicSanitize(input)).toBe(expected);
  });

  test('should preserve allowed tags', () => {
    const input = '<p>This is <b>bold</b> and <i>italic</i> text</p>';
    expect(basicSanitize(input)).toBe(input);
  });

  test('should handle non-string inputs', () => {
    const input = { test: 'value' };
    expect(basicSanitize(input)).toBe(input);
  });
});

// Test strict sanitizer
describe('Strict Sanitizer', () => {
  const { strictSanitize } = require('../../src/sanitizers/strictSanitizer');

  test('should remove most HTML tags', () => {
    const input = '<div><p>Text</p><img src="image.jpg" /></div>';
    const expected = '<p>Text</p>';
    expect(strictSanitize(input)).toBe(expected);
  });
});

// Test context-aware sanitizer
describe('Context-Aware Sanitizer', () => {
  const {
    contextAwareSanitize,
    CONTEXT_TYPES,
  } = require('../../src/sanitizers/contextAwareSanitizer');

  test('should sanitize HTML context', () => {
    const input = '<p>Text</p><script>alert("XSS")</script>';
    const expected = '<p>Text</p>';
    expect(contextAwareSanitize(input, { context: CONTEXT_TYPES.HTML })).toBe(
      expected
    );
  });

  test('should sanitize URL context', () => {
    const input = 'javascript:alert("XSS")';
    const expected = '#';
    expect(contextAwareSanitize(input, { context: CONTEXT_TYPES.URL })).toBe(
      expected
    );
  });
});

// tests/integration/protection.test.js (continued)
describe('XSS Protection Pipeline', () => {
  const { sanitizeInput } = require('../../src/index');

  test('should protect against common XSS attacks', () => {
    const attacks = [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">',
      '<a href="javascript:alert(\'XSS\')">Click me</a>',
      '<div onmouseover="alert(\'XSS\')">Hover over me</div>',
      '"><script>alert(document.cookie)</script>',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<svg onload="alert(\'XSS\')"></svg>',
    ];

    attacks.forEach((attack) => {
      const sanitized = sanitizeInput(attack);
      expect(sanitized).not.toContain('script');
      expect(sanitized).not.toContain('alert');
      expect(sanitized).not.toContain('javascript:');
      expect(sanitized).not.toMatch(/on\w+=/);
    });
  });

  test('should handle different policies correctly', () => {
    const input = '<p>Text</p><img src="image.jpg" alt="Image">';

    // Basic policy should preserve img tag
    const basicSanitized = sanitizeInput(input, { policy: 'basic' });
    expect(basicSanitized).toContain('img');

    // Strict policy should remove img tag
    const strictSanitized = sanitizeInput(input, { policy: 'strict' });
    expect(strictSanitized).not.toContain('img');
  });

  test('should apply context-aware sanitization', () => {
    const input = '<a href="https://example.com">Link</a>';

    // HTML context should preserve the link
    const htmlSanitized = sanitizeInput(input, {
      context: 'html',
      policy: 'contextAware',
    });
    expect(htmlSanitized).toContain('<a href=');

    // Attribute context should remove tags
    const attrSanitized = sanitizeInput(input, {
      context: 'attribute',
      policy: 'contextAware',
    });
    expect(attrSanitized).not.toContain('<');
    expect(attrSanitized).not.toContain('>');
  });

  test('should detect and handle DOM-based XSS threats', () => {
    const domAttack = 'location.hash.substring(1)';

    // Should throw on threats when configured
    expect(() => {
      sanitizeInput(domAttack, { throwOnThreat: true });
    }).toThrow();

    // Should sanitize without throwing when not configured to throw
    const sanitized = sanitizeInput(domAttack);
    expect(sanitized).not.toEqual(domAttack);
  });
});
