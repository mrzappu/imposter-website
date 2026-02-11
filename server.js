// server.js - Complete with Cart System, Order Logs & Discord Payment Integration
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
  )`);

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
  )`);

  // Create announcements table
  db.run(`CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER
  )`);

  // Create cart table
  db.run(`CREATE TABLE IF NOT EXISTS cart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    UNIQUE(user_id, product_id)
  )`);

  // Create orders table with payment fields
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER DEFAULT 1,
    total_price REAL,
    status TEXT DEFAULT 'pending',
    payment_method TEXT DEFAULT 'discord',
    payment_status TEXT DEFAULT 'waiting',
    discord_contact TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  )`);

  // Create order_logs table for activity tracking
  db.run(`CREATE TABLE IF NOT EXISTS order_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    user_id INTEGER,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Create cart_logs table for cart activity
  db.run(`CREATE TABLE IF NOT EXISTS cart_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  )`);

  console.log('✅ All database tables ready');

  // Insert default products
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
          [product.name, product.subtitle, product.price, product.price_suffix, product.icon, product.features, 'active']
        );
      }
    });
  });

  // Create default admin account
  setTimeout(async () => {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (!row) {
        db.run(`INSERT INTO users (username, email, password, role) 
                VALUES (?, ?, ?, ?)`,
          ['admin', 'admin@imposter.ff', hashedPassword, 'admin']
        );
        console.log('✅ Default admin created - Username: admin, Password: admin123');
      }
    });
  }, 500);
});

console.log('✅ Database connected: imposter.db');

// ============ MIDDLEWARE ============
const requireLogin = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

const requireAdmin = (req, res, next) => {
  if (req.session.role === 'admin') {
    next();
  } else {
    res.redirect('/');
  }
};

// ============ ROUTES ============
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

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.get('/cart', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'cart.html'));
});

// ============ USER API ENDPOINTS ============
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

// ============ PRODUCT API ENDPOINTS ============
app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM products WHERE status = "active" ORDER BY id ASC', [], (err, rows) => {
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

// ============ CART API ENDPOINTS ============
// Get user cart
app.get('/api/cart', requireLogin, (req, res) => {
  db.all(`
    SELECT c.*, p.name, p.price, p.price_suffix, p.icon, p.features
    FROM cart c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?
  `, [req.session.userId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    let total = 0;
    rows.forEach(row => {
      total += row.price * row.quantity;
      if (row.features) {
        try {
          row.features = JSON.parse(row.features);
        } catch (e) {
          row.features = [];
        }
      }
    });
    
    res.json({ items: rows, total: total });
  });
});

// Add to cart
app.post('/api/cart/add', requireLogin, (req, res) => {
  const { product_id, quantity = 1 } = req.body;
  
  db.run(`
    INSERT INTO cart (user_id, product_id, quantity) 
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, product_id) 
    DO UPDATE SET quantity = quantity + ?
  `, [req.session.userId, product_id, quantity, quantity], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    // Log cart activity
    db.run(`
      INSERT INTO cart_logs (user_id, product_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [req.session.userId, product_id, 'add', `Added ${quantity} item(s) to cart`]);
    
    res.json({ success: true });
  });
});

// Update cart quantity
app.post('/api/cart/update', requireLogin, (req, res) => {
  const { product_id, quantity } = req.body;
  
  if (quantity <= 0) {
    // Remove item if quantity is 0
    return db.run(`
      DELETE FROM cart WHERE user_id = ? AND product_id = ?
    `, [req.session.userId, product_id], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true, removed: true });
    });
  }
  
  db.run(`
    UPDATE cart SET quantity = ? 
    WHERE user_id = ? AND product_id = ?
  `, [quantity, req.session.userId, product_id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    db.run(`
      INSERT INTO cart_logs (user_id, product_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [req.session.userId, product_id, 'update', `Updated quantity to ${quantity}`]);
    
    res.json({ success: true });
  });
});

// Remove from cart
app.post('/api/cart/remove', requireLogin, (req, res) => {
  const { product_id } = req.body;
  
  db.run(`
    DELETE FROM cart 
    WHERE user_id = ? AND product_id = ?
  `, [req.session.userId, product_id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    db.run(`
      INSERT INTO cart_logs (user_id, product_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [req.session.userId, product_id, 'remove', 'Removed from cart']);
    
    res.json({ success: true });
  });
});

// Clear cart
app.post('/api/cart/clear', requireLogin, (req, res) => {
  db.run(`DELETE FROM cart WHERE user_id = ?`, [req.session.userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    db.run(`
      INSERT INTO cart_logs (user_id, action, details) 
      VALUES (?, ?, ?)
    `, [req.session.userId, 'clear', 'Cart cleared']);
    
    res.json({ success: true });
  });
});

// Get cart logs (user activity)
app.get('/api/cart/logs', requireLogin, (req, res) => {
  db.all(`
    SELECT cl.*, p.name as product_name
    FROM cart_logs cl
    LEFT JOIN products p ON cl.product_id = p.id
    WHERE cl.user_id = ?
    ORDER BY cl.created_at DESC
    LIMIT 50
  `, [req.session.userId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// ============ ORDER API ENDPOINTS ============
// Create order with Discord payment
app.post('/api/orders/create', requireLogin, (req, res) => {
  const { product_id, quantity = 1, discord_contact, notes } = req.body;
  
  // Get product price
  db.get('SELECT price, name FROM products WHERE id = ?', [product_id], (err, product) => {
    if (err || !product) {
      res.status(500).json({ error: 'Product not found' });
      return;
    }
    
    const total_price = product.price * quantity;
    
    db.run(`
      INSERT INTO orders (user_id, product_id, quantity, total_price, payment_method, discord_contact, notes, status, payment_status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      req.session.userId, 
      product_id, 
      quantity, 
      total_price, 
      'discord', 
      discord_contact || req.session.discord_username || 'Not provided',
      notes || '',
      'pending',
      'waiting'
    ], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      
      const orderId = this.lastID;
      
      // Log order creation
      db.run(`
        INSERT INTO order_logs (order_id, user_id, action, details) 
        VALUES (?, ?, ?, ?)
      `, [orderId, req.session.userId, 'create', `Order created for ${product.name} - $${total_price}`]);
      
      // Remove from cart if exists
      db.run(`DELETE FROM cart WHERE user_id = ? AND product_id = ?`, [req.session.userId, product_id]);
      
      res.json({ 
        success: true, 
        order_id: orderId,
        message: '✅ Order created! Please join Discord to complete payment.',
        discord_link: 'https://discord.gg/EYT8NmaMph'
      });
    });
  });
});

// Checkout entire cart
app.post('/api/orders/checkout', requireLogin, (req, res) => {
  const { discord_contact, notes } = req.body;
  
  // Get all cart items
  db.all(`
    SELECT c.*, p.price, p.name, p.id as product_id
    FROM cart c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?
  `, [req.session.userId], (err, cartItems) => {
    if (err || cartItems.length === 0) {
      res.status(400).json({ error: 'Cart is empty' });
      return;
    }
    
    let total = 0;
    cartItems.forEach(item => {
      total += item.price * item.quantity;
    });
    
    // Create items summary
    const itemsSummary = cartItems.map(i => `${i.quantity}x ${i.name}`).join(', ');
    const fullNotes = notes ? `${notes}\nItems: ${itemsSummary}` : `Items: ${itemsSummary}`;
    
    // Create order for first item and store all items in notes
    db.run(`
      INSERT INTO orders (user_id, product_id, quantity, total_price, payment_method, discord_contact, notes, status, payment_status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      req.session.userId, 
      cartItems[0].product_id,
      cartItems.length,
      total, 
      'discord', 
      discord_contact || req.session.discord_username || 'Not provided',
      fullNotes,
      'pending',
      'waiting'
    ], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      
      const orderId = this.lastID;
      
      // Log checkout
      db.run(`
        INSERT INTO order_logs (order_id, user_id, action, details) 
        VALUES (?, ?, ?, ?)
      `, [orderId, req.session.userId, 'checkout', `Checked out ${cartItems.length} items - $${total}`]);
      
      // Clear cart after checkout
      db.run(`DELETE FROM cart WHERE user_id = ?`, [req.session.userId]);
      
      res.json({ 
        success: true, 
        order_id: orderId,
        total: total,
        message: '✅ Order created! Please join Discord to complete payment.',
        discord_link: 'https://discord.gg/EYT8NmaMph'
      });
    });
  });
});

// Get user orders
app.get('/api/user/orders', requireLogin, (req, res) => {
  db.all(`
    SELECT o.*, p.name as product_name, p.price 
    FROM orders o 
    JOIN products p ON o.product_id = p.id 
    WHERE o.user_id = ? 
    ORDER BY o.created_at DESC
  `, [req.session.userId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get order logs
app.get('/api/user/order-logs', requireLogin, (req, res) => {
  db.all(`
    SELECT ol.*, p.name as product_name
    FROM order_logs ol
    LEFT JOIN products p ON ol.product_id = p.id
    WHERE ol.user_id = ?
    ORDER BY ol.created_at DESC
    LIMIT 50
  `, [req.session.userId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// ============ ANNOUNCEMENT API ENDPOINTS ============
app.get('/api/announcements', (req, res) => {
  db.all('SELECT * FROM announcements WHERE status = "active" ORDER BY created_at DESC LIMIT 5', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows || []);
  });
});

// ============ ADMIN API ENDPOINTS ============
// Get all orders with details
app.get('/api/admin/orders', requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      o.id, o.user_id, o.product_id, o.quantity, o.total_price, 
      o.status, o.payment_method, o.payment_status, o.discord_contact, o.notes,
      o.created_at, o.updated_at,
      u.username, u.email as user_email, u.ff_uid, u.discord_username,
      p.name as product_name, p.price
    FROM orders o
    LEFT JOIN users u ON o.user_id = u.id
    LEFT JOIN products p ON o.product_id = p.id
    ORDER BY o.created_at DESC
  `, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Update order status
app.post('/api/admin/orders/update-status', requireAdmin, (req, res) => {
  const { orderId, status, payment_status } = req.body;
  
  db.run(`
    UPDATE orders 
    SET status = ?, payment_status = ?, updated_at = CURRENT_TIMESTAMP 
    WHERE id = ?
  `, [status, payment_status || status, orderId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    // Log status change
    db.run(`
      INSERT INTO order_logs (order_id, user_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [orderId, req.session.userId, 'status_update', `Status changed to ${status}`]);
    
    res.json({ success: true });
  });
});

// Delete order
app.post('/api/admin/orders/delete', requireAdmin, (req, res) => {
  const { orderId } = req.body;
  
  // Delete logs first
  db.run(`DELETE FROM order_logs WHERE order_id = ?`, [orderId]);
  // Delete order
  db.run(`DELETE FROM orders WHERE id = ?`, [orderId], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

// Get all orders logs
app.get('/api/admin/order-logs', requireAdmin, (req, res) => {
  db.all(`
    SELECT ol.*, u.username, p.name as product_name
    FROM order_logs ol
    LEFT JOIN users u ON ol.user_id = u.id
    LEFT JOIN products p ON ol.product_id = p.id
    ORDER BY ol.created_at DESC
    LIMIT 100
  `, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get all cart logs
app.get('/api/admin/cart-logs', requireAdmin, (req, res) => {
  db.all(`
    SELECT cl.*, u.username, p.name as product_name
    FROM cart_logs cl
    LEFT JOIN users u ON cl.user_id = u.id
    LEFT JOIN products p ON cl.product_id = p.id
    ORDER BY cl.created_at DESC
    LIMIT 100
  `, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get all users
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all('SELECT id, username, email, ff_uid, role, discord_id, discord_username, created_at, last_login FROM users ORDER BY id DESC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get all products (admin)
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

// Create/Update product
app.post('/api/admin/products', requireAdmin, (req, res) => {
  const { id, name, subtitle, price, price_suffix, icon, features, status } = req.body;
  const featuresJson = JSON.stringify(features || []);
  
  if (id) {
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

// Delete product
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

// Get all announcements (admin)
app.get('/api/admin/announcements', requireAdmin, (req, res) => {
  db.all('SELECT * FROM announcements ORDER BY created_at DESC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Create announcement
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

// Update announcement
app.post('/api/admin/announcements/update', requireAdmin, (req, res) => {
  const { id, title, message, type, status } = req.body;
  db.run(
    'UPDATE announcements SET title = ?, message = ?, type = ?, status = ? WHERE id = ?',
    [title, message, type, status, id],
    (err) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true });
    }
  );
});

// Delete announcement
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

// Update user role
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

// Delete user
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
      req.session.discord_username = user.discord_username;
      
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

// ============ MAKE ADMIN TEMP ROUTE ============
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
  console.log
