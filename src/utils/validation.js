// src/utils/validation.js
/**
 * Utility module for input validation
 */

/**
 * Validate that input is a string or can be converted to string
 * @param {any} input - Input to validate
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidString(input) {
  return input !== undefined && input !== null;
}

/**
 * Validate that the policy name is supported
 * @param {string} policyName - Policy name to validate
 * @param {Array} allowedPolicies - List of allowed policies
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidPolicy(
  policyName,
  allowedPolicies = ['basic', 'strict', 'custom', 'contextAware']
) {
  return allowedPolicies.includes(policyName);
}

/**
 * Validate that the context type is supported
 * @param {string} contextType - Context type to validate
 * @param {Array} allowedContexts - List of allowed contexts
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidContext(
  contextType,
  allowedContexts = [
    'html',
    'attribute',
    'url',
    'javascript',
    'css',
    'json',
    'text',
  ]
) {
  return allowedContexts.includes(contextType);
}

/**
 * Validate custom sanitizer options
 * @param {Object} options - Options to validate
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidCustomOptions(options) {
  // Check if options is an object
  if (!options || typeof options !== 'object') {
    return false;
  }

  // Validate transform function if provided
  if (options.transform && typeof options.transform !== 'function') {
    return false;
  }

  return true;
}

/**
 * Convert input to string if possible
 * @param {any} input - Input to convert
 * @returns {string} - Converted string or empty string
 */
function toString(input) {
  if (input === undefined || input === null) {
    return '';
  }

  try {
    return String(input);
  } catch (e) {
    return '';
  }
}

module.exports = {
  isValidString,
  isValidPolicy,
  isValidContext,
  isValidCustomOptions,
  toString,
};
