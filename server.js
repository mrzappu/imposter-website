// server.js – Main Express server with Discord OAuth, Shop, Admin, Database
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Database = require('better-sqlite3');
const axios = require('axios');
const config = require('./config');
const { initBot, sendLog, giveRole } = require('./bot');

const app = express();
const db = new Database('Imposter.db');

// ==================== DATABASE SETUP ====================
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT,
        avatar TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId TEXT NOT NULL,
        productId INTEGER NOT NULL,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (productId) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId TEXT NOT NULL,
        productName TEXT NOT NULL,
        price REAL NOT NULL,
        proof TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id)
    );
`);

// Add sample products if empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
if (productCount === 0) {
    const insert = db.prepare('INSERT INTO products (name, price, description) VALUES (?, ?, ?)');
    insert.run('VIP Membership', 19.99, 'Exclusive VIP access to IMPOSTER Network');
    insert.run('Premium Pack', 29.99, 'Premium digital pack with bonus content');
    insert.run('Lifetime Access', 99.99, 'One-time payment for lifetime access');
    insert.run('Custom Role', 9.99, 'Custom colored role in Discord server');
    console.log('✅ Sample products added');
}

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session(config.session));

// Session user helper
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.isAdmin = req.session.user?.id === config.admin.discordId;
    next();
});

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Ensure uploads folder
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Multer config
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, `proof-${unique}${ext}`);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: config.upload.maxSize },
    fileFilter: (req, file, cb) => {
        if (config.upload.allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only PNG, JPG, JPEG allowed'));
        }
    }
});

// ==================== DISCORD OAUTH ====================
app.get('/auth/discord', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${config.discord.clientId}&redirect_uri=${encodeURIComponent(config.discord.redirectUri)}&response_type=code&scope=identify`;
    res.redirect(url);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/');

    try {
        // Exchange code for token
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: config.discord.clientId,
            client_secret: config.discord.clientSecret,
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.discord.redirectUri
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

        const { access_token } = tokenRes.data;

        // Get user info
        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const { id, username, avatar } = userRes.data;
        const avatarUrl = avatar ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` : null;

        // Store in DB
        const stmt = db.prepare('INSERT OR REPLACE INTO users (id, username, avatar) VALUES (?, ?, ?)');
        stmt.run(id, username, avatarUrl);

        // Save session
        req.session.user = { id, username, avatar: avatarUrl };

        // Send login log to Discord
        await sendLog('login', {
            userId: id,
            username,
            avatar: avatarUrl
        });

        res.redirect('/');
    } catch (error) {
        console.error('OAuth error:', error);
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ==================== ROUTES ====================
app.get('/', (req, res) => {
    res.render('index', { title: 'Home' });
});

app.get('/shop', (req, res) => {
    const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
    res.render('shop', { title: 'Shop', products });
});

app.post('/cart/add/:productId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    const { productId } = req.params;
    const userId = req.session.user.id;

    // Check if already in cart
    const exists = db.prepare('SELECT * FROM cart WHERE userId = ? AND productId = ?').get(userId, productId);
    if (!exists) {
        db.prepare('INSERT INTO cart (userId, productId) VALUES (?, ?)').run(userId, productId);
    }
    res.redirect('/shop');
});

app.get('/cart', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');

    const items = db.prepare(`
        SELECT c.id as cartId, p.* FROM cart c
        JOIN products p ON c.productId = p.id
        WHERE c.userId = ?
    `).all(req.session.user.id);

    const total = items.reduce((sum, item) => sum + item.price, 0);
    res.render('cart', { title: 'Cart', items, total });
});

app.post('/cart/remove/:cartId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    db.prepare('DELETE FROM cart WHERE id = ? AND userId = ?').run(req.params.cartId, req.session.user.id);
    res.redirect('/cart');
});

app.get('/pay', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');

    const items = db.prepare(`
        SELECT p.* FROM cart c
        JOIN products p ON c.productId = p.id
        WHERE c.userId = ?
    `).all(req.session.user.id);

    if (items.length === 0) return res.redirect('/shop');

    const total = items.reduce((sum, item) => sum + item.price, 0);
    res.render('pay', { title: 'Checkout', items, total });
});

app.post('/pay/upload', upload.single('proof'), async (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    if (!req.file) return res.redirect('/pay');

    const userId = req.session.user.id;
    const items = db.prepare(`
        SELECT p.* FROM cart c
        JOIN products p ON c.productId = p.id
        WHERE c.userId = ?
    `).all(userId);

    if (items.length === 0) return res.redirect('/shop');

    const filename = req.file.filename;
    const productNames = items.map(i => i.name).join(', ');
    const total = items.reduce((sum, i) => sum + i.price, 0);

    // Create order
    const orderStmt = db.prepare(`
        INSERT INTO orders (userId, productName, price, proof, status)
        VALUES (?, ?, ?, ?, 'pending')
    `);
    const orderResult = orderStmt.run(userId, productNames, total, filename);

    // Clear cart
    db.prepare('DELETE FROM cart WHERE userId = ?').run(userId);

    // Send payment log to Discord
    await sendLog('payment', {
        userId,
        username: req.session.user.username,
        productNames,
        total,
        proofFilename: filename,
        orderId: orderResult.lastInsertRowid
    });

    res.redirect('/history');
});

app.get('/history', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');

    const orders = db.prepare(`
        SELECT * FROM orders
        WHERE userId = ?
        ORDER BY created_at DESC
    `).all(req.session.user.id);

    res.render('history', { title: 'Order History', orders });
});

app.get('/terms', (req, res) => {
    res.render('terms', { title: 'Terms & Conditions' });
});

// ==================== ADMIN ROUTES ====================
const adminOnly = (req, res, next) => {
    if (!req.session.user || req.session.user.id !== config.admin.discordId) {
        return res.status(403).send('Access denied');
    }
    next();
};

app.get('/admin', adminOnly, (req, res) => {
    const users = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
    const orders = db.prepare(`
        SELECT o.*, u.username FROM orders o
        JOIN users u ON o.userId = u.id
        ORDER BY o.created_at DESC
    `).all();

    res.render('admin', { title: 'Admin Panel', users, orders });
});

app.post('/admin/order/:orderId/:action', adminOnly, async (req, res) => {
    const { orderId, action } = req.params;
    if (!['approved', 'rejected'].includes(action)) return res.redirect('/admin');

    // Update status
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(action, orderId);

    // Get order details
    const order = db.prepare(`
        SELECT o.*, u.username, u.id as userId FROM orders o
        JOIN users u ON o.userId = u.id
        WHERE o.id = ?
    `).get(orderId);

    if (action === 'approved') {
        // Give Discord role
        await giveRole(order.userId, config.discord.autoRoleId);
        await sendLog('approved', {
            userId: order.userId,
            username: order.username,
            productName: order.productName,
            orderId
        });
    }

    res.redirect('/admin');
});

// ==================== START SERVER & BOT ====================
initBot().then(() => {
    app.listen(config.server.port, '0.0.0.0', () => {
        console.log(`
╔══════════════════════════════════════════════════════════╗
║   ██╗███╗   ███╗██████╗  ██████╗ ███████╗████████╗     ║
║   ██║████╗ ████║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝     ║
║   ██║██╔████╔██║██████╔╝██║   ██║███████╗   ██║        ║
║   ██║██║╚██╔╝██║██╔═══╝ ██║   ██║╚════██║   ██║        ║
║   ██║██║ ╚═╝ ██║██║     ╚██████╔╝███████║   ██║        ║
║   ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝   ╚═╝        ║
╠══════════════════════════════════════════════════════════╣
║   📍 Port: ${config.server.port}
║   🌐 URL: http://localhost:${config.server.port}
║   🔥 Discord Bot: Connected
║   📊 Database: Imposter.db ready
║   © IMPOSTER Network – Dev Rick                          
╚══════════════════════════════════════════════════════════╝
        `);
    });
});
