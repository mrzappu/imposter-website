// server.js – IMPOSTER Network Complete Website
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Database = require('better-sqlite3');
const axios = require('axios');
const QRCode = require('qrcode');
const config = require('./config');
const { initBot, sendLog, giveRole, getBotStatus } = require('./bot');

const app = express();
const db = new Database('Imposter.db');

// ==================== DATABASE SETUP ====================
console.log('🔧 Setting up database...');
db.pragma('foreign_keys = ON');

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
        category TEXT DEFAULT 'general',
        image TEXT,
        stock INTEGER DEFAULT 999,
        featured BOOLEAN DEFAULT 0,
        deleted BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId TEXT NOT NULL,
        productId INTEGER NOT NULL,
        quantity INTEGER DEFAULT 1,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (productId) REFERENCES products(id),
        UNIQUE(userId, productId)
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId TEXT NOT NULL,
        items TEXT NOT NULL,
        subtotal REAL NOT NULL,
        discount REAL DEFAULT 0,
        total REAL NOT NULL,
        coupon TEXT,
        proof TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS coupons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        discount_type TEXT NOT NULL,
        discount_value REAL NOT NULL,
        min_order REAL DEFAULT 0,
        max_uses INTEGER DEFAULT 1,
        used_count INTEGER DEFAULT 0,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Add sample products if empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products WHERE deleted = 0').get().count;
if (productCount === 0) {
    console.log('📦 Adding sample products...');
    const insert = db.prepare(`INSERT INTO products (name, price, description, category, featured) VALUES (?, ?, ?, ?, ?)`);
    insert.run('VIP Membership', 199.00, 'Exclusive VIP access to IMPOSTER Network', 'membership', 1);
    insert.run('Premium Pack', 299.00, 'Premium digital pack with bonus content', 'digital', 1);
    insert.run('Lifetime Access', 999.00, 'One-time payment for lifetime access', 'membership', 0);
    insert.run('Custom Role', 99.00, 'Custom colored role in Discord server', 'service', 1);
    insert.run('Booster Pack', 149.00, 'Special booster perks for 30 days', 'digital', 0);
    insert.run('Secret Vault', 499.00, 'Access to hidden content', 'membership', 0);
    console.log('✅ Sample products added');
}

// Add sample coupons if empty
const couponCount = db.prepare('SELECT COUNT(*) as count FROM coupons').get().count;
if (couponCount === 0) {
    console.log('🏷️ Adding sample coupons...');
    const insert = db.prepare(`INSERT INTO coupons (code, discount_type, discount_value, min_order, max_uses, expires_at) VALUES (?, ?, ?, ?, ?, ?)`);
    const expires = new Date(); expires.setMonth(expires.getMonth() + 1);
    insert.run('WELCOME10', 'percentage', 10, 0, 100, expires.toISOString());
    insert.run('VIP20', 'percentage', 20, 500, 50, expires.toISOString());
    insert.run('FLAT50', 'fixed', 50, 100, 30, expires.toISOString());
    console.log('✅ Sample coupons added');
}

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.isAdmin = req.session.user?.id === config.admin.discordId;
    res.locals.req = req;
    next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==================== FILE UPLOAD SETUP ====================
const uploadDir = path.join(__dirname, 'public/uploads');
const productImgDir = path.join(__dirname, 'public/product-images');
[uploadDir, productImgDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const proofStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `proof-${Date.now()}-${Math.random().toString(36).substring(7)}${path.extname(file.originalname)}`)
});

const productStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, productImgDir),
    filename: (req, file, cb) => cb(null, `product-${Date.now()}-${Math.random().toString(36).substring(7)}${path.extname(file.originalname)}`)
});

const uploadProof = multer({
    storage: proofStorage,
    limits: { fileSize: config.upload.maxSize },
    fileFilter: (req, file, cb) => config.upload.allowedTypes.includes(file.mimetype) ? cb(null, true) : cb(new Error('Invalid file type'))
});

const uploadProductImage = multer({
    storage: productStorage,
    limits: { fileSize: config.upload.maxSize },
    fileFilter: (req, file, cb) => config.upload.allowedTypes.includes(file.mimetype) ? cb(null, true) : cb(new Error('Invalid file type'))
});

// ==================== DISCORD OAUTH ====================
app.get('/auth/discord', (req, res) => {
    if (!config.discord.clientId || !config.discord.clientSecret) {
        return res.status(500).send('Discord credentials missing');
    }
    const url = `https://discord.com/api/oauth2/authorize?client_id=${config.discord.clientId}&redirect_uri=${encodeURIComponent(config.discord.redirectUri)}&response_type=code&scope=identify`;
    res.redirect(url);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code, error } = req.query;
    if (error || !code) return res.redirect('/?error=auth_failed');

    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token',
            new URLSearchParams({
                client_id: config.discord.clientId,
                client_secret: config.discord.clientSecret,
                grant_type: 'authorization_code',
                code,
                redirect_uri: config.discord.redirectUri
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
        });

        const { id, username, avatar } = userRes.data;
        const avatarUrl = avatar ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` : null;

        db.prepare('INSERT OR REPLACE INTO users (id, username, avatar) VALUES (?, ?, ?)').run(id, username, avatarUrl);
        req.session.user = { id, username, avatar: avatarUrl };
        
        req.session.save(() => {
            sendLog('login', { userId: id, username, avatar: avatarUrl }).catch(() => {});
            res.redirect('/?login=success');
        });

    } catch (error) {
        console.error('OAuth error:', error.message);
        res.redirect('/?error=auth_failed');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ==================== API ENDPOINTS ====================
app.get('/api/generate-upi-qr', async (req, res) => {
    try {
        const amount = req.query.amount || config.payment.defaultAmount;
        const upiData = `upi://pay?pa=${config.payment.upiId}&pn=IMPOSTER&am=${amount}&cu=INR&tn=${config.payment.note}`;
        const qrDataUrl = await QRCode.toDataURL(upiData, { width: 300 });
        res.json({ success: true, qrDataUrl });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/cart/count', (req, res) => {
    if (!req.session.user) return res.json({ count: 0 });
    try {
        const count = db.prepare('SELECT COUNT(*) as count FROM cart WHERE userId = ?').get(req.session.user.id).count;
        res.json({ count });
    } catch { res.json({ count: 0 }); }
});

// ==================== HOME PAGE ====================
app.get('/', (req, res) => {
    try {
        const featured = db.prepare('SELECT * FROM products WHERE featured = 1 AND (deleted = 0 OR deleted IS NULL) LIMIT 6').all();
        
        let usersCount = 0, productsCount = 0, ordersCount = 0;
        try { usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count; } catch (e) {}
        try { productsCount = db.prepare('SELECT COUNT(*) as count FROM products WHERE deleted = 0 OR deleted IS NULL').get().count; } catch (e) {}
        try { ordersCount = db.prepare('SELECT COUNT(*) as count FROM orders WHERE status = "approved"').get().count; } catch (e) {}
        
        const loginSuccess = req.query.login === 'success';
        const loginError = req.query.error;
        
        res.render('index', { 
            title: 'Home', 
            featured,
            stats: { users: usersCount, products: productsCount, orders: ordersCount },
            loginSuccess,
            loginError,
            currentPage: 'home'
        });
    } catch (error) {
        console.error('Home error:', error);
        res.status(500).send('Error loading home page');
    }
});

// ==================== SHOP PAGE ====================
app.get('/shop', (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 9;
        const offset = (page - 1) * limit;
        const category = req.query.category || 'all';
        const search = req.query.search || '';
        
        let query = 'SELECT * FROM products WHERE (deleted = 0 OR deleted IS NULL)';
        const params = [];
        
        if (category !== 'all') { query += ' AND category = ?'; params.push(category); }
        if (search) { query += ' AND (name LIKE ? OR description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
        
        const total = db.prepare(query.replace('SELECT *', 'SELECT COUNT(*) as count')).get(...params).count;
        query += ' ORDER BY featured DESC, created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        
        const products = db.prepare(query).all(...params);
        const categories = db.prepare('SELECT DISTINCT category FROM products').all();
        
        res.render('shop', { 
            title: 'Shop', 
            products, 
            categories, 
            currentPage: page, 
            totalPages: Math.ceil(total / limit), 
            category, 
            search,
            currentPage: 'shop'
        });
    } catch (error) {
        console.error('Shop error:', error);
        res.status(500).send('Error loading shop');
    }
});

// ==================== CART ROUTES ====================
app.post('/cart/add/:productId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    const { productId } = req.params;
    const userId = req.session.user.id;
    
    try {
        const existing = db.prepare('SELECT * FROM cart WHERE userId = ? AND productId = ?').get(userId, productId);
        existing 
            ? db.prepare('UPDATE cart SET quantity = quantity + 1 WHERE id = ?').run(existing.id)
            : db.prepare('INSERT INTO cart (userId, productId) VALUES (?, ?)').run(userId, productId);
    } catch (error) {}
    res.redirect(req.get('referer') || '/shop');
});

app.get('/cart', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    try {
        const items = db.prepare(`
            SELECT c.id as cartId, c.quantity, p.* FROM cart c
            JOIN products p ON c.productId = p.id
            WHERE c.userId = ? AND (p.deleted = 0 OR p.deleted IS NULL)
        `).all(req.session.user.id);
        
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        res.render('cart', { 
            title: 'Cart', 
            items, 
            subtotal,
            currentPage: 'cart'
        });
    } catch (error) {
        console.error('Cart error:', error);
        res.status(500).send('Error loading cart');
    }
});

app.post('/cart/update/:cartId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    const { quantity } = req.body;
    try {
        if (quantity < 1) {
            db.prepare('DELETE FROM cart WHERE id = ? AND userId = ?').run(req.params.cartId, req.session.user.id);
        } else {
            db.prepare('UPDATE cart SET quantity = ? WHERE id = ? AND userId = ?').run(quantity, req.params.cartId, req.session.user.id);
        }
    } catch (error) {}
    res.redirect('/cart');
});

app.post('/cart/remove/:cartId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    try {
        db.prepare('DELETE FROM cart WHERE id = ? AND userId = ?').run(req.params.cartId, req.session.user.id);
    } catch (error) {}
    res.redirect('/cart');
});

// ==================== CHECKOUT ====================
app.get('/checkout', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    try {
        const items = db.prepare(`
            SELECT c.id as cartId, c.quantity, p.* FROM cart c
            JOIN products p ON c.productId = p.id
            WHERE c.userId = ?
        `).all(req.session.user.id);
        
        if (items.length === 0) return res.redirect('/shop');
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        res.render('checkout', { 
            title: 'Checkout', 
            items, 
            subtotal, 
            discount: 0, 
            total: subtotal,
            couponCode: null, 
            error: null, 
            success: null,
            upiId: config.payment.upiId, 
            defaultAmount: config.payment.defaultAmount,
            currentPage: 'checkout'
        });
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).send('Error loading checkout');
    }
});

app.post('/checkout/apply-coupon', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    try {
        const coupon = db.prepare(`
            SELECT * FROM coupons 
            WHERE code = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
            AND (max_uses IS NULL OR used_count < max_uses)
        `).get(req.body.code);
        
        if (!coupon) return res.json({ valid: false, error: 'Invalid coupon' });
        req.session.coupon = coupon;
        res.json({ valid: true, discount: coupon.discount_value, type: coupon.discount_type });
    } catch (error) {
        res.json({ valid: false, error: 'Error applying coupon' });
    }
});

app.post('/checkout/place-order', uploadProof.single('proof'), async (req, res) => {
    if (!req.session.user || !req.file) return res.redirect('/checkout');
    
    const userId = req.session.user.id;
    try {
        const items = db.prepare(`
            SELECT c.quantity, p.* FROM cart c
            JOIN products p ON c.productId = p.id
            WHERE c.userId = ?
        `).all(userId);
        
        if (items.length === 0) return res.redirect('/shop');
        
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        let discount = 0, couponCode = null;
        
        if (req.session.coupon) {
            const coupon = req.session.coupon;
            discount = coupon.discount_type === 'percentage' ? subtotal * (coupon.discount_value / 100) : coupon.discount_value;
            db.prepare('UPDATE coupons SET used_count = used_count + 1 WHERE id = ?').run(coupon.id);
            couponCode = coupon.code;
            delete req.session.coupon;
        }
        
        const total = Math.max(0, subtotal - discount);
        const itemsJson = JSON.stringify(items.map(i => ({ id: i.id, name: i.name, price: i.price, quantity: i.quantity })));
        
        const orderResult = db.prepare(`
            INSERT INTO orders (userId, items, subtotal, discount, total, coupon, proof, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        `).run(userId, itemsJson, subtotal, discount, total, couponCode, req.file.filename);
        
        db.prepare('DELETE FROM cart WHERE userId = ?').run(userId);
        
        sendLog('payment', {
            userId, 
            username: req.session.user.username, 
            avatar: req.session.user.avatar,
            items: items.map(i => `${i.quantity}x ${i.name}`).join(', '),
            total, 
            proofFilename: req.file.filename, 
            orderId: orderResult.lastInsertRowid
        }).catch(() => {});
        
        res.redirect('/history?success=order_placed');
        
    } catch (error) {
        console.error('Order error:', error);
        res.redirect('/checkout?error=order_failed');
    }
});

// ==================== ORDER HISTORY ====================
app.get('/history', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    try {
        const orders = db.prepare('SELECT * FROM orders WHERE userId = ? ORDER BY created_at DESC').all(req.session.user.id);
        orders.forEach(o => { 
            try { o.itemsParsed = JSON.parse(o.items); } catch { o.itemsParsed = []; } 
        });
        res.render('history', { 
            title: 'Order History', 
            orders, 
            success: req.query.success,
            currentPage: 'history'
        });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).send('Error loading history');
    }
});

// ==================== TERMS PAGE ====================
app.get('/terms', (req, res) => {
    res.render('terms', { 
        title: 'Terms & Conditions',
        currentPage: 'terms'
    });
});

// ==================== ADMIN ROUTES ====================
const adminOnly = (req, res, next) => {
    if (!req.session.user || req.session.user.id !== config.admin.discordId) {
        return res.status(403).send('Access denied');
    }
    next();
};

// Admin Dashboard
app.get('/admin', adminOnly, (req, res) => {
    try {
        let usersCount = 0, productsCount = 0, ordersCount = 0, pendingCount = 0, approvedCount = 0, couponsCount = 0;
        
        try { usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count; } catch (e) {}
        try { productsCount = db.prepare('SELECT COUNT(*) as count FROM products WHERE deleted = 0 OR deleted IS NULL').get().count; } catch (e) {}
        try { ordersCount = db.prepare('SELECT COUNT(*) as count FROM orders').get().count; } catch (e) {}
        try { pendingCount = db.prepare('SELECT COUNT(*) as count FROM orders WHERE status = "pending"').get().count; } catch (e) {}
        try { approvedCount = db.prepare('SELECT COUNT(*) as count FROM orders WHERE status = "approved"').get().count; } catch (e) {}
        try { couponsCount = db.prepare('SELECT COUNT(*) as count FROM coupons').get().count; } catch (e) {}
        
        const stats = {
            users: usersCount,
            products: productsCount,
            orders: ordersCount,
            pendingOrders: pendingCount,
            approvedOrders: approvedCount,
            coupons: couponsCount
        };
        
        const recentOrders = db.prepare(`
            SELECT o.*, u.username FROM orders o
            JOIN users u ON o.userId = u.id
            ORDER BY o.created_at DESC
            LIMIT 10
        `).all();
        
        recentOrders.forEach(order => {
            try {
                order.itemsParsed = JSON.parse(order.items);
                order.itemCount = order.itemsParsed.length;
            } catch (e) {
                order.itemCount = 0;
            }
        });
        
        res.render('admin', { 
            title: 'Admin Dashboard', 
            stats,
            recentOrders,
            section: 'dashboard',
            query: req.query || {},
            currentPage: 'admin'
        });
    } catch (error) {
        console.error('Admin error:', error);
        res.status(500).render('admin', { 
            title: 'Admin Dashboard', 
            stats: { users: 0, products: 0, orders: 0, pendingOrders: 0, approvedOrders: 0, coupons: 0 },
            recentOrders: [],
            section: 'dashboard',
            query: {},
            currentPage: 'admin'
        });
    }
});

// Admin Products
app.get('/admin/products', adminOnly, (req, res) => {
    try {
        const products = db.prepare('SELECT * FROM products WHERE deleted = 0 OR deleted IS NULL ORDER BY created_at DESC').all();
        res.render('admin', { 
            title: 'Manage Products', 
            products,
            section: 'products',
            query: req.query || {},
            currentPage: 'admin'
        });
    } catch (error) {
        console.error('Admin products error:', error);
        res.status(500).send('Error loading products');
    }
});

app.get('/admin/products/add', adminOnly, (req, res) => {
    res.render('admin', { 
        title: 'Add Product', 
        product: null,
        section: 'product-form',
        query: req.query || {},
        currentPage: 'admin'
    });
});

app.post('/admin/products/add', adminOnly, uploadProductImage.single('image'), (req, res) => {
    try {
        const { name, price, description, category, stock, featured } = req.body;
        db.prepare(`
            INSERT INTO products (name, price, description, category, stock, featured, image)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            name, 
            parseFloat(price), 
            description, 
            category || 'general', 
            parseInt(stock) || 999, 
            featured ? 1 : 0, 
            req.file ? `/product-images/${req.file.filename}` : null
        );
        
        res.redirect('/admin/products?success=added');
    } catch (error) {
        console.error('Add product error:', error);
        res.redirect('/admin/products?error=add_failed');
    }
});

app.get('/admin/products/edit/:id', adminOnly, (req, res) => {
    try {
        const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
        if (!product) return res.redirect('/admin/products?error=not_found');
        res.render('admin', { 
            title: 'Edit Product', 
            product,
            section: 'product-form',
            query: req.query || {},
            currentPage: 'admin'
        });
    } catch (error) {
        res.redirect('/admin/products?error=edit_failed');
    }
});

app.post('/admin/products/edit/:id', adminOnly, uploadProductImage.single('image'), (req, res) => {
    try {
        const { name, price, description, category, stock, featured } = req.body;
        const id = req.params.id;
        
        if (req.file) {
            const old = db.prepare('SELECT image FROM products WHERE id = ?').get(id);
            if (old?.image) {
                const oldPath = path.join(__dirname, 'public', old.image);
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            db.prepare(`
                UPDATE products SET name=?, price=?, description=?, category=?, stock=?, featured=?, image=?
                WHERE id=?
            `).run(name, parseFloat(price), description, category, parseInt(stock), featured ? 1 : 0, `/product-images/${req.file.filename}`, id);
        } else {
            db.prepare(`
                UPDATE products SET name=?, price=?, description=?, category=?, stock=?, featured=?
                WHERE id=?
            `).run(name, parseFloat(price), description, category, parseInt(stock), featured ? 1 : 0, id);
        }
        
        res.redirect('/admin/products?success=updated');
    } catch (error) {
        console.error('Update error:', error);
        res.redirect('/admin/products?error=update_failed');
    }
});

app.post('/admin/products/delete/:id', adminOnly, (req, res) => {
    const id = req.params.id;
    try {
        const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
        if (!product) return res.redirect('/admin/products?error=not_found');

        db.prepare('DELETE FROM cart WHERE productId = ?').run(id);

        const inOrders = db.prepare('SELECT items FROM orders').all().some(order => {
            try { return JSON.parse(order.items).some(item => item.id === parseInt(id)); } 
            catch { return false; }
        });

        if (inOrders) {
            db.prepare('UPDATE products SET deleted = 1 WHERE id = ?').run(id);
            return res.redirect('/admin/products?success=deleted_soft');
        }

        if (product.image) {
            const imagePath = path.join(__dirname, 'public', product.image);
            if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
        }

        db.prepare('DELETE FROM products WHERE id = ?').run(id);
        res.redirect('/admin/products?success=deleted');
        
    } catch (error) {
        console.error('Delete error:', error);
        res.redirect('/admin/products?error=delete_failed');
    }
});

// Admin Coupons
app.get('/admin/coupons', adminOnly, (req, res) => {
    try {
        const coupons = db.prepare('SELECT * FROM coupons ORDER BY created_at DESC').all();
        coupons.forEach(c => { 
            if (c.expires_at) c.expires_at_formatted = new Date(c.expires_at).toLocaleDateString();
            c.created_at_formatted = new Date(c.created_at).toLocaleDateString();
        });
        res.render('admin', { 
            title: 'Manage Coupons', 
            coupons,
            section: 'coupons',
            query: req.query || {},
            currentPage: 'admin'
        });
    } catch (error) {
        console.error('Admin coupons error:', error);
        res.status(500).send('Error loading coupons');
    }
});

app.get('/admin/coupons/generate', adminOnly, (req, res) => {
    res.render('admin', { 
        title: 'Generate Coupon', 
        coupon: null,
        section: 'coupon-form',
        query: req.query || {},
        currentPage: 'admin'
    });
});

function generateCouponCode(prefix = '', length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = prefix ? prefix + '-' : '';
    for (let i = 0; i < length; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
    return code;
}

app.post('/admin/coupons/generate', adminOnly, (req, res) => {
    try {
        const { discount_type, discount_value, min_order, max_uses, expires_days, custom_code, code_prefix } = req.body;
        if (!discount_type || !discount_value) return res.redirect('/admin/coupons/generate?error=missing_fields');
        
        let code = custom_code || generateCouponCode(code_prefix, 8);
        if (db.prepare('SELECT id FROM coupons WHERE code = ?').get(code)) {
            return res.redirect('/admin/coupons/generate?error=code_exists');
        }
        
        const expires_at = expires_days ? new Date(Date.now() + expires_days * 24 * 60 * 60 * 1000).toISOString() : null;
        
        db.prepare(`
            INSERT INTO coupons (code, discount_type, discount_value, min_order, max_uses, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(code, discount_type, parseFloat(discount_value), parseFloat(min_order) || 0, parseInt(max_uses) || 1, expires_at);
        
        res.redirect('/admin/coupons?success=generated');
    } catch (error) {
        console.error('Generate coupon error:', error);
        res.redirect('/admin/coupons/generate?error=generate_failed');
    }
});

app.post('/admin/coupons/delete/:id', adminOnly, (req, res) => {
    try {
        db.prepare('DELETE FROM coupons WHERE id = ?').run(req.params.id);
        res.redirect('/admin/coupons?success=deleted');
    } catch (error) {
        console.error('Delete coupon error:', error);
        res.redirect('/admin/coupons?error=delete_failed');
    }
});

// Admin Orders
app.get('/admin/orders', adminOnly, (req, res) => {
    try {
        const status = req.query.status || 'all';
        let query = `SELECT o.*, u.username FROM orders o JOIN users u ON o.userId = u.id`;
        const params = [];
        if (status !== 'all') { query += ' WHERE o.status = ?'; params.push(status); }
        query += ' ORDER BY o.created_at DESC';
        
        const orders = params.length ? db.prepare(query).all(...params) : db.prepare(query).all();
        orders.forEach(o => { 
            try { o.itemsParsed = JSON.parse(o.items); o.itemCount = o.itemsParsed.length; } 
            catch { o.itemCount = 0; } 
        });
        
        res.render('admin', { 
            title: 'Manage Orders', 
            orders,
            currentStatus: status,
            section: 'orders',
            query: req.query || {},
            currentPage: 'admin'
        });
    } catch (error) {
        console.error('Admin orders error:', error);
        res.status(500).send('Error loading orders');
    }
});

app.post('/admin/orders/:orderId/:action', adminOnly, async (req, res) => {
    try {
        const { orderId, action } = req.params;
        if (!['approved', 'rejected'].includes(action)) return res.redirect('/admin/orders');
        
        db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(action, orderId);
        
        if (action === 'approved') {
            const order = db.prepare(`
                SELECT o.*, u.username, u.avatar, u.id as userId FROM orders o
                JOIN users u ON o.userId = u.id WHERE o.id = ?
            `).get(orderId);
            
            if (order) {
                await giveRole(order.userId, config.discord.autoRoleId);
                let itemsText = '';
                try { 
                    itemsText = JSON.parse(order.items).map(i => `${i.quantity}x ${i.name}`).join(', '); 
                } catch { 
                    itemsText = order.items; 
                }
                sendLog('approved', { 
                    userId: order.userId, 
                    username: order.username, 
                    avatar: order.avatar, 
                    items: itemsText, 
                    orderId 
                }).catch(() => {});
            }
        }
        
        res.redirect('/admin/orders');
    } catch (error) {
        console.error('Order action error:', error);
        res.status(500).send('Error processing order');
    }
});

// ==================== 404 HANDLER ====================
app.use((req, res) => {
    res.status(404).render('404', { 
        title: 'Page Not Found',
        currentPage: '404'
    });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
let botStatus = { connected: false, botTag: null, servers: 0 };

initBot().then(() => {
    botStatus = getBotStatus();
    console.log('\n✅ BOT FULLY OPERATIONAL');
}).catch(err => {
    console.error('Bot init error:', err.message);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║   ██╗███╗   ███╗██████╗  ██████╗ ███████╗████████╗     ║
║   ██║████╗ ████║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝     ║
║   ██║██╔████╔██║██████╔╝██║   ██║███████╗   ██║        ║
║   ██║██║╚██╔╝██║██╔═══╝ ██║   ██║╚════██║   ██║        ║
║   ██║██║ ╚═╝ ██║██║     ╚██████╔╝███████║   ██║        ║
║   ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝   ╚═╝        ║
╠══════════════════════════════════════════════════════════╣
║   📍 Port: ${PORT}
║   🌐 URL: ${config.server.baseUrl}
║   🔥 Website: ✅ ONLINE
║   🤖 Discord Bot: ${botStatus.connected ? '✅ CONNECTED' : '⏳ CONNECTING...'}
║   📊 Bot Tag: ${botStatus.botTag || 'Starting up...'}
║   🗄️ Database: SQLite (Imposter.db)
║   © IMPOSTER Network                          
╚══════════════════════════════════════════════════════════╝
    `);
});
