// src/utils/logger.js
/**
 * Enhanced logger module for tracking XSS detection and sanitization actions
 */

// Log levels
const LOG_LEVELS = {
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
};

// Default configuration
let config = {
  logLevel: LOG_LEVELS.INFO,
  enableConsole: true,
  enableFile: false,
  filePath: './xss-protection.log',
  anonymizeData: false,
};

/**
 * Configure the logger
 * @param {Object} options - Logger configuration options
 */
function configure(options = {}) {
  config = { ...config, ...options };
}

/**
 * Log a message at the specified level
 * @param {string} level - Log level
 * @param {string} message - Log message
 * @param {Object} data - Additional data to log
 */
function log(level, message, data = {}) {
  if (!shouldLog(level)) return;

  const timestamp = new Date().toISOString();
  const logData = {
    timestamp,
    level,
    message,
    ...data,
  };

  // Anonymize sensitive data if configured
  if (config.anonymizeData) {
    logData.data = anonymize(logData.data);
  }

  // Console logging
  if (config.enableConsole) {
    const consoleMethod = getConsoleMethod(level);
    consoleMethod(`[${timestamp}] [${level.toUpperCase()}] ${message}`, data);
  }

  // File logging (stub - would require additional implementation)
  if (config.enableFile) {
    // Implementation for file logging would go here
    // This would typically use fs.appendFile in Node.js
  }
}

/**
 * Log a detected threat
 * @param {string} input - The input that triggered the threat detection
 * @param {Object} threatInfo - Additional threat information
 */
function logThreat(input, threatInfo = {}) {
  const data = {
    input: config.anonymizeData ? anonymize(input) : input.substring(0, 100),
    ...threatInfo,
  };

  log(LOG_LEVELS.WARN, 'XSS threat detected', data);
}

/**
 * Log a sanitization action
 * @param {string} policy - The policy applied
 * @param {string} before - Input before sanitization
 * @param {string} after - Input after sanitization
 */
function logSanitization(policy, before, after) {
  const data = {
    policy,
    changed: before !== after,
    beforeLength: before.length,
    afterLength: after.length,
  };

  if (!config.anonymizeData) {
    data.before = before.substring(0, 50);
    data.after = after.substring(0, 50);
  }

  log(LOG_LEVELS.INFO, 'Content sanitized', data);
}

/**
 * Anonymize potentially sensitive data
 * @param {any} data - Data to anonymize
 * @returns {any} - Anonymized data
 */
function anonymize(data) {
  if (typeof data === 'string') {
    return data.length > 0
      ? `[String: ${data.length} chars]`
      : '[Empty string]';
  }

  if (typeof data === 'object' && data !== null) {
    const result = Array.isArray(data) ? [] : {};

    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        result[key] = anonymize(data[key]);
      }
    }

    return result;
  }

  return data;
}

/**
 * Get the appropriate console method for the log level
 * @param {string} level - Log level
 * @returns {Function} - Console method
 */
function getConsoleMethod(level) {
  switch (level) {
    case LOG_LEVELS.DEBUG:
      return console.debug;
    case LOG_LEVELS.INFO:
      return console.info;
    case LOG_LEVELS.WARN:
      return console.warn;
    case LOG_LEVELS.ERROR:
      return console.error;
    default:
      return console.log;
  }
}

/**
 * Check if the log level should be logged
 * @param {string} level - Log level to check
 * @returns {boolean} - True if the level should be logged
 */
function shouldLog(level) {
  const levels = Object.values(LOG_LEVELS);
  const configLevelIndex = levels.indexOf(config.logLevel);
  const logLevelIndex = levels.indexOf(level);

  return logLevelIndex >= configLevelIndex;
}

module.exports = {
  configure,
  log,
  logThreat,
  logSanitization,
  LOG_LEVELS,
};
