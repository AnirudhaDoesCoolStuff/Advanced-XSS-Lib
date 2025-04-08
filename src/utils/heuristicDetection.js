/**
 * Heuristic-based detection for XSS payloads that might bypass regex patterns
 */

/**
 * Entropy calculation for detecting obfuscated payloads
 * Higher entropy often indicates obfuscated code
 * @param {string} str - String to analyze
 * @returns {number} - Shannon entropy value
 */
function calculateEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;

  const len = str.length;
  const frequencies = {};

  // Count character frequencies
  for (let i = 0; i < len; i++) {
    const char = str.charAt(i);
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  // Calculate entropy
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Count character type distribution (useful for detecting encodings)
 * @param {string} str - String to analyze
 * @returns {Object} - Character type distribution
 */
function getCharTypeDistribution(str) {
  if (!str || typeof str !== 'string') return {};

  const dist = {
    lowercase: 0,
    uppercase: 0,
    numeric: 0,
    special: 0,
    whitespace: 0,
    hex: 0,
    control: 0,
  };

  for (let i = 0; i < str.length; i++) {
    const char = str.charAt(i);
    const code = str.charCodeAt(i);

    if (/[a-z]/.test(char)) dist.lowercase++;
    else if (/[A-Z]/.test(char)) dist.uppercase++;
    else if (/[0-9]/.test(char)) dist.numeric++;
    else if (/\s/.test(char)) dist.whitespace++;
    else if (/[0-9a-fA-F]/.test(char)) dist.hex++;
    else if (code < 32 || code === 127) dist.control++;
    else dist.special++;
  }

  // Convert to percentages
  const total = str.length;
  for (const key in dist) {
    dist[key] = (dist[key] / total) * 100;
  }

  return dist;
}

/**
 * Check if a string has suspicious characteristics
 * @param {string} str - String to analyze
 * @returns {Object} - Analysis results
 */
function analyzeSuspiciousCharacteristics(str) {
  if (!str || typeof str !== 'string') return { suspicious: false };

  const entropy = calculateEntropy(str);
  const charDist = getCharTypeDistribution(str);

  const results = {
    entropy,
    charDist,
    suspicious: false,
    reasons: [],
  };

  // Check for high entropy (possible obfuscation)
  if (entropy > 5.0) {
    results.suspicious = true;
    results.reasons.push('High entropy');
  }

  // Check for hex encoding
  if (charDist.hex > 50 && charDist.special > 5) {
    results.suspicious = true;
    results.reasons.push('Possible hex encoding');
  }

  // Check for unusual character distribution
  if (charDist.special > 30) {
    results.suspicious = true;
    results.reasons.push('High percentage of special characters');
  }

  // Check for control characters
  if (charDist.control > 0) {
    results.suspicious = true;
    results.reasons.push('Contains control characters');
  }

  return results;
}

/**
 * Check if a string contains potential JS payloads by analyzing patterns
 * @param {string} str - String to analyze
 * @returns {boolean} - True if suspicious
 */
function hasJsPayloadCharacteristics(str) {
  if (!str || typeof str !== 'string') return false;

  // Check for common JS patterns
  const jsPatterns = [
    /eval\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /Function\s*\(/i,
    /document\s*\./i,
    /window\s*\./i,
    /location\s*\./i,
    /alert\s*\(/i,
    /console\s*\./i,
    /\s*=\s*function\s*\(/i,
    /\(\s*function\s*\(/i,
    /\.replace\s*\(/i,
    /\.fromCharCode\s*\(/i,
    /\.createElement\s*\(/i,
    /\.appendChild\s*\(/i,
    /\.insertBefore\s*\(/i,
  ];

  for (const pattern of jsPatterns) {
    if (pattern.test(str)) {
      return true;
    }
  }

  return false;
}

module.exports = {
  calculateEntropy,
  getCharTypeDistribution,
  analyzeSuspiciousCharacteristics,
  hasJsPayloadCharacteristics,
};
