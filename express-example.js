// express-example.js
const express = require('express');
const bodyParser = require('body-parser');
const { createXssMiddleware } = require('./src/middleware/expressMiddleware');

const app = express();

// Parse JSON and URL-encoded bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Apply XSS protection to all routes
app.use(
  createXssMiddleware({
    policy: 'strict',
    blockSuspicious: true,
    logThreats: true,
  })
);

// Create a simple HTML form
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>XSS Protection Test</title></head>
      <body>
        <h1>XSS Protection Test</h1>
        <form method="POST" action="/submit">
          <label for="name">Name:</label>
          <input type="text" id="name" name="name"><br><br>
          
          <label for="comment">Comment:</label>
          <textarea id="comment" name="comment"></textarea><br><br>
          
          <button type="submit">Submit</button>
        </form>
      </body>
    </html>
  `);
});

// Handle form submission
app.post('/submit', (req, res) => {
  // The middleware already sanitized the input
  const { name, comment } = req.body;

  res.send(`
    <html>
      <head><title>Submitted Content</title></head>
      <body>
        <h1>Submitted Content (Sanitized)</h1>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Comment:</strong> ${comment}</p>
        <a href="/">Back to form</a>
      </body>
    </html>
  `);
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Express server running at http://localhost:${PORT}`);
});
