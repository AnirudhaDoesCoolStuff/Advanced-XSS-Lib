// src/index.js
const { purifyHtml, sanitizeWithOptions } = require('./core/htmlParser');
const {
  isXSSThreat,
  isDOMBasedThreat,
  analyzeThreat,
} = require('./core/threatDetection');
const {
  applyPolicy,
  getSanitizer,
  getAllPolicies,
} = require('./core/policyManager');
const {
  contextAwareSanitize,
  CONTEXT_TYPES,
} = require('./sanitizers/contextAwareSanitizer');
const logger = require('./utils/logger');
const validation = require('./utils/validation');

/**
 * Main sanitization function
 * @param {string} input - The input to sanitize
 * @param {Object} options - Sanitization options
 * @param {string} options.policy - The sanitization policy to use
 * @param {string} options.context - The context where the input will be used
 * @param {boolean} options.throwOnThreat - Whether to throw an error on threat detection
 * @param {boolean} options.logThreat - Whether to log detected threats
 * @returns {string} - The sanitized input
 */
function sanitizeInput(input, options = {}) {
  // Set default options
  const defaultOptions = {
    policy: 'basic',
    context: null,
    throwOnThreat: false,
    logThreat: true,
  };

  const mergedOptions = { ...defaultOptions, ...options };

  // Convert input to string if needed
  if (!validation.isValidString(input)) {
    return '';
  }

  const stringInput = validation.toString(input);

  // Detect threats
  const threatInfo = analyzeThreat(stringInput);

  if (threatInfo.isThreat) {
    if (mergedOptions.logThreat) {
      logger.logThreat(stringInput, threatInfo);
    }

    if (mergedOptions.throwOnThreat) {
      throw new Error('XSS threat detected in input');
    }
  }

  // Sanitize based on context if provided
  if (
    mergedOptions.context &&
    validation.isValidContext(mergedOptions.context)
  ) {
    return contextAwareSanitize(stringInput, {
      context: mergedOptions.context,
    });
  }

  // Apply the specified policy
  const sanitized = applyPolicy(stringInput, mergedOptions.policy, options);

  // Log sanitization if needed
  if (mergedOptions.logThreat) {
    logger.logSanitization(mergedOptions.policy, stringInput, sanitized);
  }

  return sanitized;
}

/**
 * Check if input contains potential XSS threats
 * @param {string} input - The input to check
 * @returns {Object} - Threat analysis information
 */
function detectThreat(input) {
  return analyzeThreat(input);
}

/**
 * Configure the library
 * @param {Object} options - Configuration options
 */
function configure(options = {}) {
  logger.configure(options.logger || {});
}

// Export all necessary functions
module.exports = {
  sanitizeInput,
  detectThreat,
  configure,
  policies: getAllPolicies(),
  contexts: CONTEXT_TYPES,
  utils: {
    purifyHtml,
    sanitizeWithOptions,
  },
};
