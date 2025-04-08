// src/middleware/expressMiddleware.js
/**
 * Express middleware for XSS protection
 */

const { sanitizeInput, detectThreat } = require('../index');

/**
 * Creates an Express middleware for XSS protection
 * @param {Object} options - Middleware options
 * @returns {Function} - Express middleware function
 */
function createXssMiddleware(options = {}) {
  const defaultOptions = {
    sanitize: true,
    sanitizeParams: true,
    sanitizeBody: true,
    sanitizeQuery: true,
    sanitizeHeaders: false,
    blockSuspicious: true,
    logThreats: true,
    policy: 'strict',
    excludePaths: [],
    excludeParams: [],
  };

  const mergedOptions = { ...defaultOptions, ...options };

  return function xssProtectionMiddleware(req, res, next) {
    // Skip excluded paths
    if (mergedOptions.excludePaths.some((path) => req.path.startsWith(path))) {
      return next();
    }

    try {
      // Sanitize request parameters
      if (mergedOptions.sanitize) {
        if (mergedOptions.sanitizeParams && req.params) {
          sanitizeObject(req.params, mergedOptions);
        }

        if (mergedOptions.sanitizeQuery && req.query) {
          sanitizeObject(req.query, mergedOptions);
        }

        if (mergedOptions.sanitizeBody && req.body) {
          sanitizeObject(req.body, mergedOptions);
        }

        if (mergedOptions.sanitizeHeaders && req.headers) {
          // Only sanitize safe-to-modify headers
          const safeHeaders = ['referer', 'user-agent', 'origin'];
          for (const header of safeHeaders) {
            if (req.headers[header]) {
              req.headers[header] = sanitizeInput(req.headers[header], {
                policy: mergedOptions.policy,
                logThreat: mergedOptions.logThreats,
              });
            }
          }
        }
      }

      next();
    } catch (error) {
      if (mergedOptions.blockSuspicious) {
        res.status(403).json({
          error: 'Potential security threat detected',
          message: 'Request blocked for security reasons',
        });
      } else {
        next(error);
      }
    }
  };
}

/**
 * Recursively sanitize an object's string properties
 * @param {Object} obj - Object to sanitize
 * @param {Object} options - Sanitization options
 */
function sanitizeObject(obj, options) {
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      // Skip excluded parameters
      if (options.excludeParams.includes(key)) {
        continue;
      }

      if (typeof obj[key] === 'string') {
        obj[key] = sanitizeInput(obj[key], {
          policy: options.policy,
          logThreat: options.logThreats,
          throwOnThreat: options.blockSuspicious,
        });
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeObject(obj[key], options);
      }
    }
  }
}

module.exports = { createXssMiddleware };
