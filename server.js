// server.js - Main Node.js application with SQLite database (imposter.db)
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: 'imposter-ff-panel-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // set to true if using HTTPS (Render uses HTTPS)
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Database setup - impostor.db
const db = new sqlite3.Database('./imposter.db');

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  ff_uid TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME
)`);

// Middleware to check if user is logged in
const requireLogin = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Login POST handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.sendFile(path.join(__dirname, 'login.html'), { error: 'Database error' });
    }
    
    if (!user) {
      return res.sendFile(path.join(__dirname, 'login.html'), { error: 'User not found' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.sendFile(path.join(__dirname, 'login.html'), { error: 'Invalid password' });
    }
    
    // Update last login
    db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    
    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.email = user.email;
    
    res.redirect('/');
  });
});

// Register page
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Register POST handler
app.post('/register', async (req, res) => {
  const { username, email, password, ff_uid } = req.body;
  
  // Validation
  if (!username || !email || !password) {
    return res.sendFile(path.join(__dirname, 'register.html'), { error: 'All fields required' });
  }
  
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    db.run(
      'INSERT INTO users (username, email, password, ff_uid) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, ff_uid || null],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.sendFile(path.join(__dirname, 'register.html'), { 
              error: 'Username or email already exists' 
            });
          }
          console.error(err);
          return res.sendFile(path.join(__dirname, 'register.html'), { error: 'Registration failed' });
        }
        
        // Auto login after registration
        req.session.userId = this.lastID;
        req.session.username = username;
        req.session.email = email;
        
        res.redirect('/');
      }
    );
  } catch (error) {
    console.error(error);
    res.sendFile(path.join(__dirname, 'register.html'), { error: 'Server error' });
  }
});

// Main store page (protected)
app.get('/', requireLogin, (req, res) => {
  // Read the HTML file and replace username placeholder
  let html = require('fs').readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  html = html.replace(/\{\{username\}\}/g, req.session.username);
  res.send(html);
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// API endpoint to get all users (for testing)
app.get('/api/users', (req, res) => {
  db.all('SELECT id, username, email, ff_uid, created_at, last_login FROM users', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`IMP0STER Panel running on port ${PORT}`);
  console.log(`Login: http://localhost:${PORT}/login`);
  console.log(`Register: http://localhost:${PORT}/register`);
  console.log(`Store: http://localhost:${PORT}/`);
});
