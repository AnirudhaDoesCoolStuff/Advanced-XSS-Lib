// src/sanitizers/strictSanitizer.js
const { sanitizeWithOptions } = require('../core/htmlParser');

/**
 * A strict sanitizer that removes all but a limited set of safe HTML elements and attributes
 * @param {string} input - The input string to sanitize
 * @param {Object} options - Additional sanitization options
 * @returns {string} - The sanitized string
 */
function strictSanitize(input, options = {}) {
  if (typeof input !== 'string') return input;

  // Define very strict options
  const strictOptions = {
    allowedTags: ['b', 'i', 'p', 'br'],
    allowedAttributes: {},
    allowedSchemes: [],
    disallowedTagsMode: 'discard',
  };

  // Merge with user options, but prioritize security constraints
  const mergedOptions = { ...strictOptions, ...options };

  return sanitizeWithOptions(input, mergedOptions);
}

module.exports = { strictSanitize };
