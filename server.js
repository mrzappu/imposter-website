// server.js - Fixed version
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'imposter-ff-panel-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

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
  res.render('login', { error: null });
});

// Login POST handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Database error' });
    }
    
    if (!user) {
      return res.render('login', { error: 'User not found' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.render('login', { error: 'Invalid password' });
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
  res.render('register', { error: null });
});

// Register POST handler
app.post('/register', async (req, res) => {
  const { username, email, password, ff_uid } = req.body;
  
  // Validation
  if (!username || !email || !password) {
    return res.render('register', { error: 'All fields required' });
  }
  
  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters' });
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
            return res.render('register', { 
              error: 'Username or email already exists' 
            });
          }
          console.error(err);
          return res.render('register', { error: 'Registration failed' });
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
    res.render('register', { error: 'Server error' });
  }
});

// Main store page (protected)
app.get('/', requireLogin, (req, res) => {
  res.render('index', { username: req.session.username });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// API endpoint to get all users (for testing)
app.get('/api/users', requireLogin, (req, res) => {
  db.all('SELECT id, username, email, ff_uid, created_at, last_login FROM users', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Health check for Render
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`IMP0STER Panel running on port ${PORT}`);
  console.log(`Login: http://localhost:${PORT}/login`);
  console.log(`Register: http://localhost:${PORT}/register`);
  console.log(`Store: http://localhost:${PORT}/`);
});
