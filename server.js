// server.js - Complete with Admin Panel, Discord, Profile
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
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Set views directory
app.set('views', path.join(__dirname, 'views'));

// Database setup
const db = new sqlite3.Database('./imposter.db');

// Create users table with admin role and discord fields
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  ff_uid TEXT,
  role TEXT DEFAULT 'user',
  discord_id TEXT,
  discord_username TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME
)`);

// Create default admin account
const createAdmin = async () => {
  const hashedPassword = await bcrypt.hash('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
          VALUES (?, ?, ?, ?)`, 
    ['admin', 'admin@imposter.ff', hashedPassword, 'admin']
  );
  console.log('✅ Default admin created - Username: admin, Password: admin123');
};
createAdmin();

console.log('✅ Database connected: imposter.db');

// Middleware to check if user is logged in
const requireLogin = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Middleware to check if user is admin
const requireAdmin = (req, res, next) => {
  if (req.session.role === 'admin') {
    next();
  } else {
    res.redirect('/');
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

// Admin Panel
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Profile Page
app.get('/profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

// ============ API ENDPOINTS ============

// Get current user info
app.get('/api/user', requireLogin, (req, res) => {
  db.get('SELECT id, username, email, ff_uid, role, discord_id, discord_username, created_at FROM users WHERE id = ?', 
    [req.session.userId], 
    (err, row) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json(row);
  });
});

// Get all users (admin only)
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all('SELECT id, username, email, ff_uid, role, discord_id, discord_username, created_at, last_login FROM users ORDER BY id DESC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Update user role (admin only)
app.post('/api/admin/update-role', requireAdmin, (req, res) => {
  const { userId, role } = req.body;
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

// Delete user (admin only)
app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body;
  db.run('DELETE FROM users WHERE id = ? AND role != "admin"', [userId], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

// Update user profile
app.post('/api/user/update', requireLogin, (req, res) => {
  const { ff_uid, discord_id, discord_username } = req.body;
  db.run('UPDATE users SET ff_uid = ?, discord_id = ?, discord_username = ? WHERE id = ?', 
    [ff_uid || null, discord_id || null, discord_username || null, req.session.userId], 
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true });
  });
});

// Make user admin (temporary route - remove after use)
app.get('/make-admin/:username', async (req, res) => {
  const { username } = req.params;
  db.run('UPDATE users SET role = "admin" WHERE username = ?', [username], (err) => {
    if (err) {
      res.send('Error: ' + err.message);
    } else {
      res.send(`✅ User "${username}" is now an admin!`);
    }
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
      req.session.role = user.role;
      
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
    const hashedPassword = await bcrypt.hash(password, 10);
    
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
        
        req.session.userId = this.lastID;
        req.session.username = username;
        req.session.email = email;
        req.session.role = 'user';
        
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
    if (err) console.error(err);
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

app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 IMP0STER PANEL DEPLOYED SUCCESSFULLY!');
  console.log('========================================');
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🔗 Login: http://localhost:${PORT}/login`);
  console.log(`🔗 Register: http://localhost:${PORT}/register`);
  console.log(`🔗 Store: http://localhost:${PORT}/`);
  console.log(`🔗 Admin: http://localhost:${PORT}/admin`);
  console.log(`🔗 Profile: http://localhost:${PORT}/profile`);
  console.log('========================================');
  console.log('📝 Default Admin: admin / admin123');
  console.log('========================================\n');
});
