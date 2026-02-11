// server.js - COMPLETE FIXED VERSION with proper table creation
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

// Database setup - WRAPPED IN SERIALIZE to ensure tables are created in order
const db = new sqlite3.Database('./imposter.db');

// Use serialize to ensure tables are created sequentially
db.serialize(() => {
  console.log('📦 Creating database tables...');
  
  // Create users table
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
  )`, function(err) {
    if (err) console.error('Error creating users table:', err);
    else console.log('✅ Users table ready');
  });

  // Create products table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    subtitle TEXT,
    price REAL NOT NULL,
    price_suffix TEXT,
    icon TEXT DEFAULT 'fa-bolt',
    features TEXT,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, function(err) {
    if (err) console.error('Error creating products table:', err);
    else console.log('✅ Products table ready');
  });

  // Create announcements table
  db.run(`CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER
  )`, function(err) {
    if (err) console.error('Error creating announcements table:', err);
    else console.log('✅ Announcements table ready');
  });

  // Create orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  )`, function(err) {
    if (err) console.error('Error creating orders table:', err);
    else console.log('✅ Orders table ready');
  });

  // Insert default products AFTER table is created
  setTimeout(() => {
    const defaultProducts = [
      {
        name: 'HEADSHOT ELITE',
        subtitle: 'Aimbot + Antiban',
        price: 19.99,
        price_suffix: '/month',
        icon: 'fa-bolt',
        features: JSON.stringify([
          '98% headshot rate',
          'Aim lock (undetected)',
          'Anti-ban shield',
          '24/7 private server',
          'Weekly updates',
          'Premium support'
        ])
      },
      {
        name: 'DIAMOND FLOOD',
        subtitle: 'Instant Delivery',
        price: 44.99,
        price_suffix: '/instant',
        icon: 'fa-gem',
        features: JSON.stringify([
          '+20,000 diamonds',
          'No password required',
          'Delivery in 5min',
          'Redeem code method',
          'Safe & secure',
          'No ban risk'
        ])
      },
      {
        name: 'RANK IMPOSTER',
        subtitle: 'Heroic Boost',
        price: 29.99,
        price_suffix: '/season',
        icon: 'fa-chess-queen',
        features: JSON.stringify([
          'Heroic rank boost',
          'K/D spoofing',
          'MVP unlocker',
          'Invisible mode',
          'Matchmaking bypass',
          'Anti-detection'
        ])
      },
      {
        name: 'SKULL SKINS',
        subtitle: 'Legendary Bundle',
        price: 14.99,
        price_suffix: '/unlock',
        icon: 'fa-ghost',
        features: JSON.stringify([
          '50+ legendary skins',
          'Imposter bundle',
          'Emote collector',
          'Weapon flamethrower',
          'Exclusive items',
          'Instant unlock'
        ])
      }
    ];

    defaultProducts.forEach(product => {
      db.get('SELECT id FROM products WHERE name = ?', [product.name], (err, row) => {
        if (!row) {
          db.run(`INSERT INTO products (name, subtitle, price, price_suffix, icon, features, status) 
                  VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [product.name, product.subtitle, product.price, product.price_suffix, product.icon, product.features, 'active'],
            function(err) {
              if (err) console.error('Error inserting product:', err);
            }
          );
        }
      });
    });
    console.log('✅ Default products inserted');
  }, 500); // Small delay to ensure table exists

  // Create default admin account
  setTimeout(async () => {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (!row) {
        db.run(`INSERT INTO users (username, email, password, role) 
                VALUES (?, ?, ?, ?)`,
          ['admin', 'admin@imposter.ff', hashedPassword, 'admin'],
          function(err) {
            if (err) console.error('Error creating admin:', err);
            else console.log('✅ Default admin created - Username: admin, Password: admin123');
          }
        );
      }
    });
  }, 500);
});

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

// Get all products (active)
app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM products WHERE status = "active" ORDER BY id ASC', [], (err, rows) => {
    if (err) {
      console.error('Error fetching products:', err);
      res.status(500).json({ error: err.message });
      return;
    }
    // Parse features JSON
    rows.forEach(row => {
      if (row.features) {
        try {
          row.features = JSON.parse(row.features);
        } catch (e) {
          row.features = [];
        }
      }
    });
    res.json(rows);
  });
});

// Get single product by ID
app.get('/api/products/:id', (req, res) => {
  db.get('SELECT * FROM products WHERE id = ?', [req.params.id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (row && row.features) {
      try {
        row.features = JSON.parse(row.features);
      } catch (e) {
        row.features = [];
      }
    }
    res.json(row);
  });
});

// Get active announcements
app.get('/api/announcements', (req, res) => {
  db.all('SELECT * FROM announcements WHERE status = "active" ORDER BY created_at DESC LIMIT 5', [], (err, rows) => {
    if (err) {
      console.error('Error fetching announcements:', err);
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows || []);
  });
});

// Create order
app.post('/api/orders/create', requireLogin, (req, res) => {
  const { product_id } = req.body;
  db.run(
    'INSERT INTO orders (user_id, product_id, status) VALUES (?, ?, ?)',
    [req.session.userId, product_id, 'pending'],
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true, order_id: this.lastID });
    }
  );
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

// ============ ADMIN API ENDPOINTS ============

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

// Get all products (admin - includes inactive)
app.get('/api/admin/products', requireAdmin, (req, res) => {
  db.all('SELECT * FROM products ORDER BY id ASC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    rows.forEach(row => {
      if (row.features) {
        try {
          row.features = JSON.parse(row.features);
        } catch (e) {
          row.features = [];
        }
      }
    });
    res.json(rows);
  });
});

// Create/Update product (admin only)
app.post('/api/admin/products', requireAdmin, (req, res) => {
  const { id, name, subtitle, price, price_suffix, icon, features, status } = req.body;
  const featuresJson = JSON.stringify(features || []);
  
  if (id) {
    // Update existing product
    db.run(
      'UPDATE products SET name = ?, subtitle = ?, price = ?, price_suffix = ?, icon = ?, features = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [name, subtitle, price, price_suffix, icon, featuresJson, status, id],
      function(err) {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }
        res.json({ success: true, id: id });
      }
    );
  } else {
    // Create new product
    db.run(
      'INSERT INTO products (name, subtitle, price, price_suffix, icon, features, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, subtitle, price, price_suffix, icon, featuresJson, status || 'active'],
      function(err) {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }
        res.json({ success: true, id: this.lastID });
      }
    );
  }
});

// Delete product (admin only)
app.post('/api/admin/products/delete', requireAdmin, (req, res) => {
  const { id } = req.body;
  db.run('DELETE FROM products WHERE id = ?', [id], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

// Create announcement (admin)
app.post('/api/admin/announcements', requireAdmin, (req, res) => {
  const { title, message, type, status } = req.body;
  db.run(
    'INSERT INTO announcements (title, message, type, status, created_by) VALUES (?, ?, ?, ?, ?)',
    [title, message, type || 'info', status || 'active', req.session.userId],
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Delete announcement (admin)
app.post('/api/admin/announcements/delete', requireAdmin, (req, res) => {
  const { id } = req.body;
  db.run('DELETE FROM announcements WHERE id = ?', [id], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
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

// Make user admin (temporary route)
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
      
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      
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
