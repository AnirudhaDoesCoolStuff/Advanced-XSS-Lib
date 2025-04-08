# Advanced XSS Protection Library

A comprehensive library for detecting and preventing Cross-Site Scripting (XSS) attacks in web applications.

## Features

- Multiple sanitization policies (basic, strict, custom, context-aware)
- HTML parsing using industry-standard libraries (DOMPurify, sanitize-html)
- Context-aware sanitization for different input destinations (HTML, URLs, JavaScript, etc.)
- Detection of DOM-based XSS attacks
- Heuristic analysis for encoded and obfuscated attacks
- Comprehensive logging and threat tracking
- Express and Koa middleware support
- Highly configurable and extensible

## Installation

```bash
npm install advanced-xss-protection-lib
```

## Basic Usage

```javascript
const { sanitizeInput } = require('advanced-xss-protection-lib');

// Basic sanitization
const userInput = '<script>alert("XSS")</script><p>Hello World</p>';
const sanitized = sanitizeInput(userInput);
console.log(sanitized); // <p>Hello World</p>

// Using different policies
const strictlySanitized = sanitizeInput(userInput, { policy: 'strict' });

// Context-aware sanitization
const urlInput = 'javascript:alert("XSS")';
const safePath = sanitizeInput(urlInput, {
  policy: 'contextAware',
  context: 'url',
});
console.log(safePath); // '#'
```

## Middleware Usage

### Express

```javascript
const express = require('express');
const {
  createXssMiddleware,
} = require('advanced-xss-protection-lib/middleware/express');

const app = express();

// Apply XSS protection to all routes
app.use(
  createXssMiddleware({
    policy: 'strict',
    blockSuspicious: true,
  })
);

app.get('/api/data', (req, res) => {
  // All input is already sanitized
  res.json({ message: 'Data retrieved successfully' });
});
```

### Koa

```javascript
const Koa = require('koa');
const {
  createKoaXssMiddleware,
} = require('advanced-xss-protection-lib/middleware/koa');

const app = new Koa();

// Apply XSS protection to all routes
app.use(
  createKoaXssMiddleware({
    policy: 'strict',
    blockSuspicious: true,
  })
);

app.use(async (ctx) => {
  // All input is already sanitized
  ctx.body = { message: 'Data retrieved successfully' };
});
```

## Configuration Options

### Main Sanitization Options

| Option        | Type    | Default | Description                                                       |
| ------------- | ------- | ------- | ----------------------------------------------------------------- |
| policy        | string  | 'basic' | Sanitization policy ('basic', 'strict', 'custom', 'contextAware') |
| context       | string  | null    | Context where input will be used (HTML, URL, JS, etc.)            |
| throwOnThreat | boolean | false   | Whether to throw an error when a threat is detected               |
| logThreat     | boolean | true    | Whether to log detected threats                                   |

### Middleware Options

| Option          | Type    | Default | Description                                           |
| --------------- | ------- | ------- | ----------------------------------------------------- |
| sanitize        | boolean | true    | Whether to sanitize input at all                      |
| sanitizeParams  | boolean | true    | Whether to sanitize route parameters                  |
| sanitizeBody    | boolean | true    | Whether to sanitize request body                      |
| sanitizeQuery   | boolean | true    | Whether to sanitize query string parameters           |
| sanitizeHeaders | boolean | false   | Whether to sanitize certain safe headers              |
| blockSuspicious | boolean | true    | Whether to block requests with suspicious input       |
| excludePaths    | array   | []      | Array of path prefixes to exclude from sanitization   |
| excludeParams   | array   | []      | Array of parameter names to exclude from sanitization |

## License

MIT

## Contributing

Pull requests and issues are welcome! Please see the contributing guidelines for more information.
