// src/sanitizers/contextAwareSanitizer.js
const { sanitizeWithOptions } = require('../core/htmlParser');

/**
 * Context types for different sanitization strategies
 */
const CONTEXT_TYPES = {
  HTML: 'html',
  ATTR: 'attribute',
  URL: 'url',
  JS: 'javascript',
  CSS: 'css',
  JSON: 'json',
  TEXT: 'text',
};

/**
 * Context-aware sanitizer that applies different rules based on where the input will be used
 * @param {string} input - The input to sanitize
 * @param {Object} options - Sanitization options
 * @param {string} options.context - The context where the input will be used
 * @returns {string} - Sanitized input
 */
function contextAwareSanitize(input, options = {}) {
  if (typeof input !== 'string') return input;

  const context = options.context || CONTEXT_TYPES.HTML;

  switch (context) {
    case CONTEXT_TYPES.HTML:
      return sanitizeHtml(input);

    case CONTEXT_TYPES.ATTR:
      // For attribute context, we remove all quotes and angle brackets
      return input.replace(/['"<>]/g, '').replace(/on\w+/gi, ''); // Remove event handlers

    case CONTEXT_TYPES.URL:
      // For URLs, ensure it's a safe URL
      if (/^(https?|mailto|tel):/i.test(input)) {
        return input.replace(/["'<>]/g, '');
      }
      return '#'; // Default to a safe URL

    case CONTEXT_TYPES.JS:
      // For JS context, we encode everything to prevent execution
      return JSON.stringify(input);

    case CONTEXT_TYPES.CSS:
      // For CSS context, remove potential expressions and functions
      return input
        .replace(/expression\s*\(/gi, '')
        .replace(/url\s*\(/gi, '')
        .replace(/calc\s*\(/gi, '')
        .replace(/var\s*\(/gi, '');

    case CONTEXT_TYPES.JSON:
      // For JSON context, ensure it's valid JSON or escape it
      try {
        JSON.parse(input); // Check if valid JSON
        return input;
      } catch (e) {
        return JSON.stringify(input);
      }

    case CONTEXT_TYPES.TEXT:
    default:
      // For plain text context, remove all HTML
      return input.replace(/<[^>]*>/g, '');
  }
}

// Helper function for HTML context
function sanitizeHtml(input) {
  return sanitizeWithOptions(input, {
    allowedTags: ['p', 'b', 'i', 'u', 'a', 'ul', 'ol', 'li', 'br'],
    allowedAttributes: {
      a: ['href', 'target'],
    },
  });
}

module.exports = {
  contextAwareSanitize,
  CONTEXT_TYPES,
};
