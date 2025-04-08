// src/core/policyManager.js
const { basicSanitize } = require('../sanitizers/basicSanitizer');
const { strictSanitize } = require('../sanitizers/strictSanitizer');
const { customSanitize } = require('../sanitizers/customSanitizer');
const { contextAwareSanitize } = require('../sanitizers/contextAwareSanitizer');

/**
 * Policy configurations for different security levels
 */
const policies = {
  basic: {
    name: 'basic',
    description: 'Basic XSS protection allowing common HTML tags',
    sanitizer: basicSanitize,
  },
  strict: {
    name: 'strict',
    description: 'Strict sanitization removing almost all HTML',
    sanitizer: strictSanitize,
  },
  custom: {
    name: 'custom',
    description: 'Custom sanitization with user-defined rules',
    sanitizer: customSanitize,
  },
  contextAware: {
    name: 'contextAware',
    description: 'Context-aware sanitization based on input destination',
    sanitizer: contextAwareSanitize,
  },
};

/**
 * Get the appropriate sanitizer based on the policy name
 * @param {string} policyName - The sanitization policy to use
 * @returns {Function} - The corresponding sanitization function
 */
function getSanitizer(policyName = 'basic') {
  return policies[policyName]?.sanitizer || policies.basic.sanitizer;
}

/**
 * Apply a sanitization policy to the input
 * @param {string} input - The input to sanitize
 * @param {string} policyName - The policy name to apply
 * @param {Object} options - Additional options for the sanitizer
 * @returns {string} - The sanitized input
 */
function applyPolicy(input, policyName = 'basic', options = {}) {
  const sanitizer = getSanitizer(policyName);
  return sanitizer(input, options);
}

/**
 * Get policy details
 * @param {string} policyName - The policy name
 * @returns {Object} - Policy details
 */
function getPolicyDetails(policyName) {
  return policies[policyName] || policies.basic;
}

/**
 * Get all available policies
 * @returns {Object} - All policies
 */
function getAllPolicies() {
  return policies;
}

/**
 * Log sanitizer choice for debugging/auditing
 * @param {string} policyName - The policy used
 * @param {Object} context - Additional context information
 */
function logSanitizerChoice(policyName, context = {}) {
  const policy = getPolicyDetails(policyName);
  console.log(
    `Sanitizer policy chosen: ${policy.name} - ${policy.description}`,
    context
  );
}

module.exports = {
  getSanitizer,
  applyPolicy,
  getPolicyDetails,
  getAllPolicies,
  logSanitizerChoice,
};
