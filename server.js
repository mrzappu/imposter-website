// server.js - Complete Working Version for Render
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
  secret: process.env.SESSION_SECRET || 'imposter-ff-panel-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to false for Render HTTP
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Set views directory for HTML files
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

// Serve HTML files
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// ============ API ENDPOINTS ============

// Get current user info
app.get('/api/user', requireLogin, (req, res) => {
  db.get('SELECT id, username, email, ff_uid, created_at FROM users WHERE id = ?', 
    [req.session.userId], 
    (err, row) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json(row);
  });
});

// ============ LOGIN HANDLER ============
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.redirect('/login?error=Username and password required');
  }
  
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.redirect('/login?error=Database error');
    }
    
    if (!user) {
      return res.redirect('/login?error=User not found');
    }
    
    try {
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.redirect('/login?error=Invalid password');
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
      res.redirect('/login?error=Login failed');
    }
  });
});

// ============ REGISTER HANDLER ============
app.post('/register', async (req, res) => {
  const { username, email, password, ff_uid } = req.body;
  
  // Validation
  if (!username || !email || !password) {
    return res.redirect('/register?error=All fields are required');
  }
  
  if (username.length < 3) {
    return res.redirect('/register?error=Username must be at least 3 characters');
  }
  
  if (password.length < 6) {
    return res.redirect('/register?error=Password must be at least 6 characters');
  }
  
  if (!email.includes('@') || !email.includes('.')) {
    return res.redirect('/register?error=Please enter a valid email');
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
            if (err.message.includes('username')) {
              return res.redirect('/register?error=Username already taken');
            } else {
              return res.redirect('/register?error=Email already registered');
            }
          }
          console.error(err);
          return res.redirect('/register?error=Registration failed');
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
    res.redirect('/register?error=Server error');
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

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString()
  });
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
