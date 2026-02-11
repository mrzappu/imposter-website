// server.js - Complete Fixed Version for Render
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');

// Suppress deprecation warnings
process.noDeprecation = true;

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Set up SQLite session store
const SQLiteStore = require('connect-sqlite3')(session);

// Session configuration with SQLite store (production ready)
app.use(session({
  store: new SQLiteStore({ 
    db: 'sessions.db',
    dir: './'
  }),
  secret: process.env.SESSION_SECRET || 'imposter-ff-panel-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (Render HTTPS)
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'strict'
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

console.log('✅ Database connected: imposter.db');

// Middleware to check if user is logged in
const requireLogin = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// ============ ROUTES ============

// Home/Store page (protected)
app.get('/', requireLogin, (req, res) => {
  res.render('index', { 
    username: req.session.username,
    email: req.session.email
  });
});

// ============ LOGIN ROUTES ============
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.render('login', { error: 'Username and password required' });
  }
  
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Database error' });
    }
    
    if (!user) {
      return res.render('login', { error: 'User not found' });
    }
    
    try {
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
    } catch (error) {
      console.error(error);
      res.render('login', { error: 'Login failed' });
    }
  });
});

// ============ REGISTER ROUTES ============
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password, ff_uid } = req.body;
  
  // Validation
  if (!username || !email || !password) {
    return res.render('register', { error: 'All fields are required' });
  }
  
  if (username.length < 3) {
    return res.render('register', { error: 'Username must be at least 3 characters' });
  }
  
  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters' });
  }
  
  if (!email.includes('@') || !email.includes('.')) {
    return res.render('register', { error: 'Please enter a valid email' });
  }
  
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Insert user
    db.run(
      'INSERT INTO users (username, email, password, ff_uid) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, ff_uid || null],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            if (err.message.includes('username')) {
              return res.render('register', { error: 'Username already taken' });
            } else {
              return res.render('register', { error: 'Email already registered' });
            }
          }
          console.error(err);
          return res.render('register', { error: 'Registration failed. Please try again.' });
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
    res.render('register', { error: 'Server error. Please try again.' });
  }
});

// ============ LOGOUT ============
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
});

// ============ API ENDPOINTS (Protected) ============
app.get('/api/users', requireLogin, (req, res) => {
  db.all('SELECT id, username, email, ff_uid, created_at, last_login FROM users', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.get('/api/user', requireLogin, (req, res) => {
  db.get('SELECT id, username, email, ff_uid, created_at, last_login FROM users WHERE id = ?', 
    [req.session.userId], 
    (err, row) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json(row);
  });
});

// ============ HEALTH CHECK (for Render) ============
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ============ 404 HANDLER ============
app.use((req, res) => {
  res.status(404).render('login', { error: 'Page not found. Please login.' });
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('login', { error: 'Something went wrong! Please try again.' });
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 IMP0STER PANEL DEPLOYED SUCCESSFULLY!');
  console.log('========================================');
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Login URL: https://imposter-website.onrender.com/login`);
  console.log(`🔗 Register URL: https://imposter-website.onrender.com/register`);
  console.log(`🔗 Store URL: https://imposter-website.onrender.com/`);
  console.log('========================================\n');
});
