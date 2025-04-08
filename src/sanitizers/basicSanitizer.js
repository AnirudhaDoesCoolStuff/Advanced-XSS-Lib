// src/sanitizers/basicSanitizer.js
const { purifyHtml } = require('../core/htmlParser');

/**
 * A basic sanitizer that allows common HTML tags but removes potentially dangerous elements and attributes
 * @param {string} input - The input string to sanitize
 * @param {Object} options - Additional sanitization options
 * @returns {string} - The sanitized string
 */
function basicSanitize(input, options = {}) {
  if (typeof input !== 'string') return input;

  // Use DOMPurify with basic settings
  return purifyHtml(input);
}

module.exports = { basicSanitize };
