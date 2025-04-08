// src/core/htmlParser.js
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const sanitizeHtml = require('sanitize-html');

/**
 * Creates a DOMPurify instance with a virtual DOM
 * @returns {Object} - The DOMPurify instance
 */
function createSanitizer() {
  const window = new JSDOM('').window;
  return createDOMPurify(window);
}

/**
 * Sanitizes HTML using DOMPurify with basic configuration
 * @param {string} input - The HTML string to sanitize
 * @returns {string} - The sanitized HTML
 */
function purifyHtml(input) {
  if (typeof input !== 'string') return input;
  const purify = createSanitizer();
  return purify.sanitize(input, {
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'eval'],
    ALLOW_DATA_ATTR: false,
  });
}

/**
 * Sanitizes HTML using sanitize-html with custom configurations
 * @param {string} input - The HTML string to sanitize
 * @param {Object} options - Custom sanitize-html options
 * @returns {string} - The sanitized HTML
 */
function sanitizeWithOptions(input, options = {}) {
  if (typeof input !== 'string') return input;

  const defaultOptions = {
    allowedTags: [
      'b',
      'i',
      'u',
      'a',
      'p',
      'br',
      'ul',
      'ol',
      'li',
      'h1',
      'h2',
      'h3',
      'h4',
      'h5',
      'h6',
    ],
    allowedAttributes: {
      a: ['href', 'target'],
      '*': ['class'],
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    disallowedTagsMode: 'discard',
  };

  const mergedOptions = { ...defaultOptions, ...options };
  return sanitizeHtml(input, mergedOptions);
}

module.exports = { purifyHtml, sanitizeWithOptions };
