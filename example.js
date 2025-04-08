// example.js
const { sanitizeInput, detectThreat } = require('./src/index');

// Test cases
const testCases = [
  '<p>Hello world</p>',
  '<script>alert("XSS")</script>',
  '<img src="x" onerror="alert(\'XSS\')">',
  '<a href="javascript:alert(\'XSS\')">Click me</a>',
];

console.log('Testing XSS Protection Library:');
console.log('===============================\n');

testCases.forEach((input, index) => {
  console.log(`Test Case ${index + 1}:`);
  console.log(`Input: ${input}`);

  // Detect threats
  const threatInfo = detectThreat(input);
  console.log(`Is threat: ${threatInfo.isThreat}`);

  // Basic sanitization
  const basicSanitized = sanitizeInput(input, { policy: 'basic' });
  console.log(`Basic sanitized: ${basicSanitized}`);

  // Strict sanitization
  const strictSanitized = sanitizeInput(input, { policy: 'strict' });
  console.log(`Strict sanitized: ${strictSanitized}`);

  // Context-aware sanitization (HTML context)
  const contextSanitized = sanitizeInput(input, {
    policy: 'contextAware',
    context: 'html',
  });
  console.log(`Context-aware sanitized: ${contextSanitized}`);
  console.log('===============================\n');
});
