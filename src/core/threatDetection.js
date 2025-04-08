// src/core/threatDetection.js
/**
 * Enhanced threat detection module
 * Identifies various XSS attack vectors and patterns
 */

// Regex patterns to detect common XSS payloads
const threatPatterns = [
  /<script.*?>.*?<\/script>/gi, // <script> tags
  /<img.*?onerror\s*=\s*['"].*?['"].*?>/gi, // onerror attribute in img
  /<a.*?href\s*=\s*['"]javascript:.*?['"].*?>/gi, // javascript: in anchor tags
  /<.*?on\w+\s*=\s*['"].*?['"].*?>/gi, // any event handler
  /<.*?style\s*=\s*['"].*?expression\s*?.*?['"].*?>/gi, // CSS expressions
  /javascript\s*:.*?['"]/gi, // Inline javascript protocols
  /\/\*.*?\*\//g, // CSS comment injections
  /%3C.*?%3E/gi, // Encoded < > symbols
  /<.*?src\s*=\s*['"].*?data:.*?['"].*?>/gi, // Data URI exploits
  /eval\s*\(/gi, // eval() function
  /document\.cookie/gi, // Cookie access
  /document\.location/gi, // Location access
  /document\.write/gi, // document.write usage
  /localStorage/gi, // localStorage access
  /sessionStorage/gi, // sessionStorage access
  /\\_x[0-9A-F]{4}_/gi, // Unicode escapes
  /fromCharCode/gi, // String.fromCharCode method
  /String\.fromCharCode/gi, // String.fromCharCode fully qualified
  /\&#x[0-9a-f]+;/gi, // Hex character references
  /\&#\d+;/gi, // Decimal character references
];

// DOM-based XSS patterns
const domBasedPatterns = [
  /location\.hash/gi,
  /location\.href/gi,
  /location\.search/gi,
  /document\.referrer/gi,
  /window\.name/gi,
  /\$\(.*\)/gi, // jQuery DOM manipulation
  /innerHTML/gi,
  /outerHTML/gi,
  /insertAdjacentHTML/gi,
  /document\.write/gi,
  /document\.writeln/gi,
  /eval\s*\(/gi,
  /setTimeout\s*\(/gi,
  /setInterval\s*\(/gi,
  /new\s+Function\s*\(/gi,
];

/**
 * Detect potential XSS based on patterns
 * @param {string} input - The input to check for XSS threats
 * @returns {boolean} - True if threat is detected, false otherwise
 */
function isXSSThreat(input) {
  if (!input || typeof input !== 'string') return false;

  // Check against all threat patterns
  for (const pattern of threatPatterns) {
    if (pattern.test(input)) {
      return true;
    }
  }

  // Check for common obfuscations
  const encodedPatterns = [
    /%3C.*?%3E/g, // < >
    /%3A/g, // :
    /%2F/g, // /
    /%22/g, // "
    /%27/g, // '
    /%28/g, // (
    /%29/g, // )
  ];

  for (const encodedPattern of encodedPatterns) {
    if (encodedPattern.test(input)) {
      return true;
    }
  }

  return false;
}

/**
 * Detect potential DOM-based XSS threats
 * @param {string} input - The input to check for DOM-based XSS threats
 * @returns {boolean} - True if threat is detected, false otherwise
 */
function isDOMBasedThreat(input) {
  if (!input || typeof input !== 'string') return false;

  for (const pattern of domBasedPatterns) {
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}

/**
 * Get detailed threat information
 * @param {string} input - The input to analyze
 * @returns {Object} - Object containing threat details
 */
function analyzeThreat(input) {
  if (!input || typeof input !== 'string') return { isThreat: false };

  const threats = [];

  // Check each pattern and collect matches
  threatPatterns.forEach((pattern, index) => {
    if (pattern.test(input)) {
      threats.push({
        patternIndex: index,
        pattern: pattern.toString(),
        matches: input.match(pattern),
      });
    }
  });

  // Check for DOM-based XSS
  const domThreats = [];
  domBasedPatterns.forEach((pattern, index) => {
    if (pattern.test(input)) {
      domThreats.push({
        patternIndex: index,
        pattern: pattern.toString(),
        matches: input.match(pattern),
      });
    }
  });

  return {
    isThreat: threats.length > 0 || domThreats.length > 0,
    reflectedXss: threats,
    domBasedXss: domThreats,
    input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
    timestamp: new Date().toISOString(),
  };
}

module.exports = {
  isXSSThreat,
  isDOMBasedThreat,
  analyzeThreat,
  threatPatterns,
  domBasedPatterns,
};
