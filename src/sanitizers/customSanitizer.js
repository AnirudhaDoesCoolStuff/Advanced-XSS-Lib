// src/sanitizers/customSanitizer.js
const { sanitizeWithOptions } = require('../core/htmlParser');

/**
 * A customizable sanitizer that allows developers to define their sanitization rules
 * @param {string} input - The input string to sanitize
 * @param {Object} options - Custom sanitization options
 * @returns {string} - The sanitized string
 */
function customSanitize(input, options = {}) {
  if (typeof input !== 'string') return input;

  // Apply custom transformations if provided
  if (options.transform && typeof options.transform === 'function') {
    input = options.transform(input);
  }

  // Apply custom rules with sanitize-html
  return sanitizeWithOptions(input, options);
}

module.exports = { customSanitize };
