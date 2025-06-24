require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve static files (CSS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: 3306,
});

db.connect((err) => {
  if (err) {
    console.error('❌ Failed to connect to MySQL:', err.message);
    process.exit(1);
  }
  console.log('✅ Connected to MySQL RDS');
});

app.post('/register', async (req, res) => {
  const { username, dob, email, password } = req.body;

  // Basic validation
  if (!username || !dob || !email || !password) {
    return res.status(400).send('❌ All fields are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, dob, email, password_hash) VALUES (?, ?, ?, ?)';
    db.query(query, [username, dob, email, hashedPassword], (err, results) => {
      if (err) {
        console.error('❌ Registration DB error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).send('❌ Email already registered');
        }
        return res.status(500).send('❌ Internal server error');
      }

      return res.redirect('/login');

    });
  } catch (error) {
    console.error('❌ Bcrypt hashing error:', error);
    return res.status(500).send('❌ Internal error during registration');
  }
});


// Route to serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// POST login handler
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Check if fields are missing
  if (!email || !password) {
    return res.status(400).send('❌ Email and password are required');
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('❌ Login DB error:', err);
      return res.status(500).send('❌ Internal server error');
    }

    // Check if email exists
    if (results.length === 0) {
      return res.status(401).send('❌ Login failed: Email not found');
    }

    const user = results[0];

    // Compare hashed passwords
    try {
      const match = await bcrypt.compare(password, user.password_hash);

      if (!match) {
        return res.status(401).send('❌ Login failed: Incorrect password');
      }

      // Success
      return res.status(200).send('✅ Login successful!');
    } catch (err) {
      console.error('❌ Bcrypt error:', err);
      return res.status(500).send('❌ Internal error during login');
    }
  });
});



// Simple protected dashboard page
app.get('/dashboard', (req, res) => {
  res.send('<h1>Welcome to your dashboard!</h1><p>You are logged in.</p>');
});

// Your existing registration route here (or add separately)

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
