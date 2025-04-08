// src/middleware/koa-middleware.js
/**
 * Koa middleware for XSS protection
 */

const { sanitizeInput } = require('../index');

/**
 * Creates a Koa middleware for XSS protection
 * @param {Object} options - Middleware options
 * @returns {Function} - Koa middleware function
 */
function createKoaXssMiddleware(options = {}) {
  const defaultOptions = {
    sanitize: true,
    sanitizeParams: true,
    sanitizeBody: true,
    sanitizeQuery: true,
    blockSuspicious: true,
    logThreats: true,
    policy: 'strict',
    excludePaths: [],
    excludeParams: [],
  };

  const mergedOptions = { ...defaultOptions, ...options };

  return async function xssProtectionMiddleware(ctx, next) {
    // Skip excluded paths
    if (mergedOptions.excludePaths.some((path) => ctx.path.startsWith(path))) {
      return next();
    }

    try {
      // Sanitize request parameters
      if (mergedOptions.sanitize) {
        if (mergedOptions.sanitizeParams && ctx.params) {
          sanitizeObject(ctx.params, mergedOptions);
        }

        if (mergedOptions.sanitizeQuery && ctx.query) {
          sanitizeObject(ctx.query, mergedOptions);
        }

        if (mergedOptions.sanitizeBody && ctx.request.body) {
          sanitizeObject(ctx.request.body, mergedOptions);
        }
      }

      await next();
    } catch (error) {
      if (mergedOptions.blockSuspicious) {
        ctx.status = 403;
        ctx.body = {
          error: 'Potential security threat detected',
          message: 'Request blocked for security reasons',
        };
      } else {
        throw error;
      }
    }
  };
}

// Reuse the sanitizeObject function from Express middleware
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

module.exports = { createKoaXssMiddleware };
