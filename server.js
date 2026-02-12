// server.js - COMPLETE PRODUCTION SERVER
// Features: User Auth, Products, Cart, Orders, Discord Payments, Admin Panel, Logs, Profile, Messages
// Theme: Blue Theme Support - Fully Updated

const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ MIDDLEWARE ============
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'imposter-ff-panel-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Set views directory
app.set('views', path.join(__dirname, 'views'));

// ============ DATABASE SETUP ============
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
    ip_address TEXT,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Create products table with category support
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    subtitle TEXT,
    category TEXT DEFAULT 'other',
    price REAL NOT NULL,
    price_suffix TEXT,
    icon TEXT DEFAULT 'fa-box',
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
    admin_notes TEXT,
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

  // ============ MESSAGES TABLE ============
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    recipient_id INTEGER,
    send_to_all BOOLEAN DEFAULT 0,
    subject TEXT,
    message TEXT NOT NULL,
    reply TEXT,
    priority TEXT DEFAULT 'normal',
    read BOOLEAN DEFAULT 0,
    order_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
  )`);

  console.log('✅ All database tables ready');

  // ============ INSERT DEFAULT PRODUCTS ============
  const defaultProducts = [
    // DISCORD TOOLS
    {
      name: 'DISCORD NITRO GENERATOR',
      subtitle: 'Working Discord Nitro Codes',
      category: 'discord',
      price: 9.99,
      price_suffix: '/lifetime',
      icon: 'fa-bolt',
      features: JSON.stringify([
        'Working Discord Nitro codes',
        'Monthly updated list',
        'Lifetime access',
        '24/7 support',
        'Instant delivery',
        'No ban risk'
      ])
    },
    {
      name: 'DISCORD TOKEN JOINER',
      subtitle: 'Auto Join Servers',
      category: 'discord',
      price: 24.99,
      price_suffix: '/lifetime',
      icon: 'fa-robot',
      features: JSON.stringify([
        'Join servers automatically',
        'Proxy support',
        'Multi-threaded',
        'Captcha bypass',
        'User-friendly GUI',
        'Free updates'
      ])
    },
    {
      name: 'DISCORD MASS DM BOT',
      subtitle: 'Promote Your Server',
      category: 'discord',
      price: 34.99,
      price_suffix: '/lifetime',
      icon: 'fa-envelope',
      features: JSON.stringify([
        'Send DMs to thousands',
        'Customizable messages',
        'Delay settings',
        'Proxy support',
        'Safe mode',
        'Scrape members'
      ])
    },
    {
      name: 'DISCORD ACCOUNT CREATOR',
      subtitle: 'Create Bulk Accounts',
      category: 'discord',
      price: 44.99,
      price_suffix: '/lifetime',
      icon: 'fa-user-plus',
      features: JSON.stringify([
        'Auto email verification',
        'Captcha solver',
        'Proxy support',
        'Custom usernames',
        'Save accounts to file',
        'High success rate'
      ])
    },
    
    // CODE / APPLICATION
    {
      name: 'PYTHON CHEAT ENGINE',
      subtitle: 'Memory Scanner / Hacker Tool',
      category: 'code',
      price: 49.99,
      price_suffix: '/source code',
      icon: 'fa-code',
      features: JSON.stringify([
        'Full source code included',
        'Memory scanner',
        'Value finder',
        'Address pointer',
        'Speed hack module',
        'Undetected methods'
      ])
    },
    {
      name: 'AUTO CLICKER PRO',
      subtitle: 'Advanced Automation',
      category: 'code',
      price: 14.99,
      price_suffix: '/lifetime',
      icon: 'fa-mouse-pointer',
      features: JSON.stringify([
        'Record & playback',
        'Custom hotkeys',
        'Random delays',
        'Multiple profiles',
        'Stealth mode',
        'Portable executable'
      ])
    },
    {
      name: 'MINECRAFT ALTS GENERATOR',
      subtitle: 'Premium Accounts',
      category: 'code',
      price: 19.99,
      price_suffix: '/month',
      icon: 'fa-cube',
      features: JSON.stringify([
        'Working Minecraft accounts',
        'Daily updates',
        'Email:pass format',
        'No launcher required',
        'Instant delivery',
        'Replacements included'
      ])
    },
    {
      name: 'SPOTIFY PREMIUM GEN',
      subtitle: 'Account Generator',
      category: 'code',
      price: 12.99,
      price_suffix: '/month',
      icon: 'fa-spotify',
      features: JSON.stringify([
        'Working Spotify Premium',
        'Email:pass included',
        'Works on all devices',
        'Monthly refresh',
        'No app required',
        '24/7 support'
      ])
    },
    
    // WEBSITE DEVELOPMENT
    {
      name: 'E-COMMERCE WEBSITE',
      subtitle: 'Complete HTML/CSS/JS Template',
      category: 'web',
      price: 79.99,
      price_suffix: '/full source',
      icon: 'fa-shopping-cart',
      features: JSON.stringify([
        'Responsive design',
        'Product catalog',
        'Shopping cart',
        'Checkout page',
        'Admin panel',
        'SQLite database included'
      ])
    },
    {
      name: 'ADMIN DASHBOARD',
      subtitle: 'Bootstrap 5 Template',
      category: 'web',
      price: 39.99,
      price_suffix: '/full source',
      icon: 'fa-chart-line',
      features: JSON.stringify([
        'Dark theme',
        'Charts & graphs',
        'User management',
        'Analytics dashboard',
        'Fully responsive',
        'Easy to customize'
      ])
    },
    {
      name: 'NODE.JS BOT BASE',
      subtitle: 'Discord Bot Template',
      category: 'web',
      price: 29.99,
      price_suffix: '/source code',
      icon: 'fa-node',
      features: JSON.stringify([
        'Slash commands',
        'Database setup',
        'Moderation features',
        'Economy system',
        'Music player',
        'Hosting ready'
      ])
    },
    {
      name: 'LOGIN SYSTEM',
      subtitle: 'PHP/MySQL Authentication',
      category: 'web',
      price: 24.99,
      price_suffix: '/source code',
      icon: 'fa-lock',
      features: JSON.stringify([
        'Register/Login',
        'Password hashing',
        'Session management',
        'Remember me',
        'Reset password',
        'Admin panel'
      ])
    },
    
    // BOTS
    {
      name: 'DISCORD MUSIC BOT',
      subtitle: '24/7 Music Player',
      category: 'bot',
      price: 34.99,
      price_suffix: '/hosted',
      icon: 'fa-music',
      features: JSON.stringify([
        'Play from YouTube',
        'Queue system',
        'Loop & shuffle',
        'Volume control',
        '24/7 uptime',
        'Free hosting included'
      ])
    },
    {
      name: 'TELEGRAM AUTO POSTER',
      subtitle: 'Content Automation',
      category: 'bot',
      price: 19.99,
      price_suffix: '/lifetime',
      icon: 'fa-paper-plane',
      features: JSON.stringify([
        'Auto post to channels',
        'RSS feeds',
        'Schedule posts',
        'Multiple channels',
        'Custom formatting',
        'Free updates'
      ])
    },
    {
      name: 'TWITCH DROP FARMER',
      subtitle: 'Auto Claim Drops',
      category: 'bot',
      price: 22.99,
      price_suffix: '/lifetime',
      icon: 'fa-twitch',
      features: JSON.stringify([
        'Auto watch streams',
        'Claim drops',
        'Multi-account',
        'Proxy support',
        'Stealth mode',
        'Free updates'
      ])
    },
    
    // OTHER
    {
      name: 'VPN ACCOUNTS',
      subtitle: 'Premium VPN Access',
      category: 'other',
      price: 8.99,
      price_suffix: '/month',
      icon: 'fa-shield',
      features: JSON.stringify([
        '1Gbps speed',
        'No logs policy',
        '10 countries',
        'Works with Netflix',
        'Windows/Mac/Android',
        'Instant delivery'
      ])
    },
    {
      name: 'NETFLIX ACCOUNT',
      subtitle: 'Premium 4K',
      category: 'other',
      price: 6.99,
      price_suffix: '/month',
      icon: 'fa-film',
      features: JSON.stringify([
        '4K UHD streaming',
        '4 screens',
        'No ads',
        'Download movies',
        'Profile support',
        'Replacement warranty'
      ])
    },
    {
      name: 'CANVA PRO',
      subtitle: 'Premium Design Tools',
      category: 'other',
      price: 5.99,
      price_suffix: '/month',
      icon: 'fa-paint-brush',
      features: JSON.stringify([
        'All premium templates',
        'Background remover',
        'Brand kit',
        'Content planner',
        'Magic resize',
        'Team collaboration'
      ])
    }
  ];

  defaultProducts.forEach(product => {
    db.get('SELECT id FROM products WHERE name = ?', [product.name], (err, row) => {
      if (!row) {
        db.run(`INSERT INTO products (name, subtitle, category, price, price_suffix, icon, features, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [product.name, product.subtitle, product.category, product.price, product.price_suffix, product.icon, product.features, 'active']
        );
      }
    });
  });

  // ============ CREATE DEFAULT ADMIN ACCOUNT ============
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

// ============ PAGE ROUTES ============
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

app.get('/edit-profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'edit-profile.html'));
});

app.get('/cart', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'cart.html'));
});

// ============ USER API ENDPOINTS ============
app.get('/api/user', requireLogin, (req, res) => {
  db.get('SELECT id, username, email, ff_uid, role, discord_id, discord_username, created_at, last_login FROM users WHERE id = ?', 
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

// ============ USER MESSAGES API ENDPOINTS ============
app.get('/api/user/messages', requireLogin, (req, res) => {
  db.all(`
    SELECT m.*, u.username as sender_name
    FROM messages m
    LEFT JOIN users u ON m.sender_id = u.id
    WHERE m.recipient_id = ? OR m.send_to_all = 1
    ORDER BY m.created_at DESC
  `, [req.session.userId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/api/user/messages/read', requireLogin, (req, res) => {
  const { message_id } = req.body;
  db.run(`
    UPDATE messages SET read = 1 
    WHERE id = ? AND (recipient_id = ? OR send_to_all = 1)
  `, [message_id, req.session.userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

app.post('/api/user/messages/reply', requireLogin, (req, res) => {
  const { message_id, reply } = req.body;
  
  db.get('SELECT sender_id FROM messages WHERE id = ?', [message_id], (err, message) => {
    if (err || !message) {
      res.status(500).json({ error: 'Message not found' });
      return;
    }
    
    db.run(`
      INSERT INTO messages (sender_id, recipient_id, subject, message, reply, priority) 
      VALUES (?, ?, ?, ?, ?, ?)
    `, [
      req.session.userId,
      message.sender_id,
      'RE: Customer Reply',
      reply,
      null,
      'normal'
    ], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true, id: this.lastID });
    });
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

app.get('/api/products/category/:category', (req, res) => {
  const { category } = req.params;
  db.all('SELECT * FROM products WHERE status = "active" AND category = ? ORDER BY id ASC', [category], (err, rows) => {
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

// ============ CART API ENDPOINTS ============
app.get('/api/cart', requireLogin, (req, res) => {
  db.all(`
    SELECT c.*, p.name, p.price, p.price_suffix, p.icon, p.features, p.category
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
    
    db.run(`
      INSERT INTO cart_logs (user_id, product_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [req.session.userId, product_id, 'add', `Added ${quantity} item(s) to cart`]);
    
    res.json({ success: true });
  });
});

app.post('/api/cart/update', requireLogin, (req, res) => {
  const { product_id, quantity } = req.body;
  
  if (quantity <= 0) {
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
app.post('/api/orders/create', requireLogin, (req, res) => {
  const { product_id, quantity = 1, discord_contact, notes } = req.body;
  
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
      
      db.run(`
        INSERT INTO order_logs (order_id, user_id, action, details) 
        VALUES (?, ?, ?, ?)
      `, [orderId, req.session.userId, 'create', `Order created for ${product.name} - $${total_price}`]);
      
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

app.post('/api/orders/checkout', requireLogin, (req, res) => {
  const { discord_contact, notes } = req.body;
  
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
    
    const itemsSummary = cartItems.map(i => `${i.quantity}x ${i.name}`).join(', ');
    const fullNotes = notes ? `${notes}\nItems: ${itemsSummary}` : `Items: ${itemsSummary}`;
    
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
      
      db.run(`
        INSERT INTO order_logs (order_id, user_id, action, details) 
        VALUES (?, ?, ?, ?)
      `, [orderId, req.session.userId, 'checkout', `Checked out ${cartItems.length} items - $${total}`]);
      
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
app.get('/api/admin/orders', requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      o.id, o.user_id, o.product_id, o.quantity, o.total_price, 
      o.status, o.payment_method, o.payment_status, o.discord_contact, o.notes, o.admin_notes,
      o.created_at, o.updated_at,
      u.username, u.email as user_email, u.ff_uid, u.discord_username,
      p.name as product_name, p.price, p.category
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

app.post('/api/admin/orders/update-status', requireAdmin, (req, res) => {
  const { orderId, status, payment_status, admin_notes } = req.body;
  
  db.run(`
    UPDATE orders 
    SET status = ?, payment_status = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP 
    WHERE id = ?
  `, [status, payment_status || status, admin_notes || '', orderId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    db.run(`
      INSERT INTO order_logs (order_id, user_id, action, details) 
      VALUES (?, ?, ?, ?)
    `, [orderId, req.session.userId, 'status_update', `Status changed to ${status}, Payment: ${payment_status}`]);
    
    res.json({ success: true });
  });
});

app.post('/api/admin/orders/delete', requireAdmin, (req, res) => {
  const { orderId } = req.body;
  
  db.run(`DELETE FROM order_logs WHERE order_id = ?`, [orderId]);
  db.run(`DELETE FROM orders WHERE id = ?`, [orderId], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

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

app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all('SELECT id, username, email, ff_uid, role, discord_id, discord_username, created_at, last_login FROM users ORDER BY id DESC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

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

app.post('/api/admin/products', requireAdmin, (req, res) => {
  const { id, name, subtitle, category, price, price_suffix, icon, features, status } = req.body;
  const featuresJson = JSON.stringify(features || []);
  
  if (id) {
    db.run(
      'UPDATE products SET name = ?, subtitle = ?, category = ?, price = ?, price_suffix = ?, icon = ?, features = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [name, subtitle, category || 'other', price, price_suffix, icon, featuresJson, status, id],
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
      'INSERT INTO products (name, subtitle, category, price, price_suffix, icon, features, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, subtitle, category || 'other', price, price_suffix, icon, featuresJson, status || 'active'],
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

// ============ ADMIN MESSAGES API ENDPOINTS ============
app.get('/api/admin/messages', requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      m.*,
      sender.username as sender_name,
      recipient.username as recipient_name
    FROM messages m
    LEFT JOIN users sender ON m.sender_id = sender.id
    LEFT JOIN users recipient ON m.recipient_id = recipient.id
    ORDER BY m.created_at DESC
  `, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/api/admin/messages/send', requireAdmin, (req, res) => {
  const { user_id, send_to_all, subject, message, priority, order_id } = req.body;
  
  if (send_to_all) {
    // Send to all users
    db.all('SELECT id FROM users', [], (err, users) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      
      let count = 0;
      const stmt = db.prepare(`
        INSERT INTO messages (sender_id, recipient_id, subject, message, priority, send_to_all, order_id) 
        VALUES (?, ?, ?, ?, ?, 1, ?)
      `);
      
      users.forEach(user => {
        stmt.run([req.session.userId, user.id, subject || 'Announcement', message, priority || 'normal', order_id || null]);
        count++;
      });
      
      stmt.finalize();
      res.json({ success: true, count: count });
    });
  } else {
    // Send to single user
    db.run(`
      INSERT INTO messages (sender_id, recipient_id, subject, message, priority, order_id) 
      VALUES (?, ?, ?, ?, ?, ?)
    `, [req.session.userId, user_id, subject || 'New Message', message, priority || 'normal', order_id || null], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ success: true, id: this.lastID });
    });
  }
});

app.post('/api/admin/messages/reply', requireAdmin, (req, res) => {
  const { message_id, reply } = req.body;
  
  // Get original message to get recipient
  db.get('SELECT sender_id, recipient_id, subject FROM messages WHERE id = ?', [message_id], (err, message) => {
    if (err || !message) {
      res.status(500).json({ error: 'Message not found' });
      return;
    }
    
    // Update original message with reply
    db.run(`
      UPDATE messages 
      SET reply = ?, read = 1 
      WHERE id = ?
    `, [reply, message_id], function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      
      // Create reply message
      db.run(`
        INSERT INTO messages (sender_id, recipient_id, subject, message, priority) 
        VALUES (?, ?, ?, ?, ?)
      `, [
        req.session.userId,
        message.sender_id,
        `RE: ${message.subject || 'Your Message'}`,
        reply,
        'normal'
      ], function(err) {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }
        res.json({ success: true, id: this.lastID });
      });
    });
  });
});

app.post('/api/admin/messages/delete', requireAdmin, (req, res) => {
  const { message_id } = req.body;
  
  db.run('DELETE FROM messages WHERE id = ?', [message_id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

app.post('/api/admin/messages/mark-read', requireAdmin, (req, res) => {
  const { message_id } = req.body;
  
  db.run('UPDATE messages SET read = 1 WHERE id = ?', [message_id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ success: true });
  });
});

// ============ ADMIN ANNOUNCEMENTS API ENDPOINTS ============
app.get('/api/admin/announcements', requireAdmin, (req, res) => {
  db.all('SELECT * FROM announcements ORDER BY created_at DESC', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

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

// ============ ADMIN USER MANAGEMENT API ENDPOINTS ============
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
      
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
      
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?', [ip, user.id]);
      
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
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ============ 404 HANDLER ============
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 IMP0STER PANEL DEPLOYED SUCCESSFULLY!');
  console.log('========================================');
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('========================================');
  console.log(`🔗 Login: http://localhost:${PORT}/login`);
  console.log(`🔗 Register: http://localhost:${PORT}/register`);
  console.log(`🔗 Store: http://localhost:${PORT}/`);
  console.log(`🔗 Cart: http://localhost:${PORT}/cart`);
  console.log(`🔗 Profile: http://localhost:${PORT}/profile`);
  console.log(`🔗 Edit Profile: http://localhost:${PORT}/edit-profile`);
  console.log(`🔗 Admin: http://localhost:${PORT}/admin`);
  console.log('========================================');
  console.log('📝 Default Admin: admin / admin123');
  console.log('✅ Features: Auth, Products, Cart, Orders, Discord Payments, Admin Panel, Logs, Profile, Messages');
  console.log('✅ Categories: Discord Tools, Code/Apps, Web Dev, Bots, Other');
  console.log('✅ Theme: Blue Theme Support');
  console.log('========================================\n');
});
