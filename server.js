// server.js – IMPOSTER Network v2.0 with Advanced Shop & Coupons
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Database = require('better-sqlite3');
const axios = require('axios');
const crypto = require('crypto');
const config = require('./config');
const { initBot, sendLog, giveRole } = require('./bot');

const app = express();
const db = new Database('Imposter.db');

// ==================== DATABASE SETUP WITH MIGRATION ====================
console.log('🔧 Setting up database...');

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables with correct schema
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

// ==================== DATABASE MIGRATION - FIX ORDERS TABLE ====================
try {
    // Check if orders table has the correct columns
    const tableInfo = db.prepare("PRAGMA table_info(orders)").all();
    const hasStatus = tableInfo.some(col => col.name === 'status');
    const hasApproved = tableInfo.some(col => col.name === 'approved');
    
    if (hasApproved) {
        console.log('🔄 Migrating orders table - removing deprecated columns...');
        db.exec(`
            CREATE TABLE orders_new (
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
            
            INSERT INTO orders_new (id, userId, items, subtotal, discount, total, coupon, proof, created_at)
            SELECT id, userId, items, subtotal, discount, total, coupon, proof, created_at FROM orders;
            
            DROP TABLE orders;
            ALTER TABLE orders_new RENAME TO orders;
        `);
        console.log('✅ Orders table migration complete');
    } else if (!hasStatus) {
        console.log('🔄 Adding status column to orders table...');
        db.exec(`ALTER TABLE orders ADD COLUMN status TEXT DEFAULT 'pending';`);
        console.log('✅ Status column added');
    }
} catch (err) {
    console.error('Schema migration error:', err.message);
}

// Add sample products if empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
if (productCount === 0) {
    console.log('📦 Adding sample products...');
    const insert = db.prepare(`
        INSERT INTO products (name, price, description, category, image, featured) 
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    insert.run('VIP Membership', 19.99, 'Exclusive VIP access to IMPOSTER Network', 'membership', null, 1);
    insert.run('Premium Pack', 29.99, 'Premium digital pack with bonus content', 'digital', null, 1);
    insert.run('Lifetime Access', 99.99, 'One-time payment for lifetime access', 'membership', null, 0);
    insert.run('Custom Role', 9.99, 'Custom colored role in Discord server', 'service', null, 1);
    insert.run('Booster Pack', 14.99, 'Special booster perks for 30 days', 'digital', null, 0);
    insert.run('Secret Vault', 49.99, 'Access to hidden content', 'membership', null, 0);
    
    console.log('✅ Sample products added');
}

// Add sample coupon if empty
const couponCount = db.prepare('SELECT COUNT(*) as count FROM coupons').get().count;
if (couponCount === 0) {
    console.log('🏷️ Adding sample coupons...');
    const insert = db.prepare(`
        INSERT INTO coupons (code, discount_type, discount_value, min_order, max_uses, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const expires = new Date();
    expires.setMonth(expires.getMonth() + 1);
    
    insert.run('WELCOME10', 'percentage', 10, 0, 100, expires.toISOString());
    insert.run('VIP20', 'percentage', 20, 50, 50, expires.toISOString());
    insert.run('FLAT5', 'fixed', 5, 10, 30, expires.toISOString());
    
    console.log('✅ Sample coupons added');
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
const productImgDir = path.join(__dirname, 'public/product-images');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
if (!fs.existsSync(productImgDir)) fs.mkdirSync(productImgDir, { recursive: true });

// Multer config for proof uploads
const proofStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, `proof-${unique}${ext}`);
    }
});

// Multer config for product images
const productStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, productImgDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, `product-${unique}${ext}`);
    }
});

const uploadProof = multer({
    storage: proofStorage,
    limits: { fileSize: config.upload.maxSize },
    fileFilter: (req, file, cb) => {
        if (config.upload.allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only PNG, JPG, JPEG allowed'));
        }
    }
});

const uploadProductImage = multer({
    storage: productStorage,
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
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: config.discord.clientId,
            client_secret: config.discord.clientSecret,
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.discord.redirectUri
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

        const { access_token } = tokenRes.data;

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const { id, username, avatar } = userRes.data;
        const avatarUrl = avatar ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` : null;

        const stmt = db.prepare('INSERT OR REPLACE INTO users (id, username, avatar) VALUES (?, ?, ?)');
        stmt.run(id, username, avatarUrl);

        req.session.user = { id, username, avatar: avatarUrl };

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

// ==================== HOME PAGE ====================
app.get('/', (req, res) => {
    const featured = db.prepare('SELECT * FROM products WHERE featured = 1 LIMIT 6').all();
    
    // Get stats with error handling
    let usersCount = 0, productsCount = 0, ordersCount = 0;
    try { usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count; } catch (e) {}
    try { productsCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count; } catch (e) {}
    try { ordersCount = db.prepare('SELECT COUNT(*) as count FROM orders WHERE status = "approved"').get().count; } catch (e) {}
    
    const stats = {
        users: usersCount,
        products: productsCount,
        orders: ordersCount
    };
    
    res.render('index', { 
        title: 'Home', 
        featured,
        stats
    });
});

// ==================== SHOP PAGE ====================
app.get('/shop', (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 9;
        const offset = (page - 1) * limit;
        const category = req.query.category || 'all';
        const search = req.query.search || '';
        
        let query = 'SELECT * FROM products WHERE 1=1';
        const params = [];
        
        if (category !== 'all') {
            query += ' AND category = ?';
            params.push(category);
        }
        
        if (search) {
            query += ' AND (name LIKE ? OR description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        
        const totalQuery = query.replace('SELECT *', 'SELECT COUNT(*) as count');
        const total = db.prepare(totalQuery).get(...params).count;
        
        query += ' ORDER BY featured DESC, created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        
        const products = db.prepare(query).all(...params);
        const categories = db.prepare('SELECT DISTINCT category FROM products WHERE category IS NOT NULL').all();
        
        res.render('shop', {
            title: 'Shop',
            products,
            categories,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            category,
            search
        });
    } catch (error) {
        console.error('Shop error:', error);
        res.status(500).send('Error loading shop');
    }
});

// ==================== CART SYSTEM ====================
app.post('/cart/add/:productId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    const { productId } = req.params;
    const userId = req.session.user.id;
    
    try {
        const existing = db.prepare('SELECT * FROM cart WHERE userId = ? AND productId = ?').get(userId, productId);
        
        if (existing) {
            db.prepare('UPDATE cart SET quantity = quantity + 1 WHERE id = ?').run(existing.id);
        } else {
            db.prepare('INSERT INTO cart (userId, productId) VALUES (?, ?)').run(userId, productId);
        }
    } catch (error) {
        console.error('Cart add error:', error);
    }
    
    res.redirect(req.get('referer') || '/shop');
});

app.get('/cart', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    
    try {
        const items = db.prepare(`
            SELECT c.id as cartId, c.quantity, p.* FROM cart c
            JOIN products p ON c.productId = p.id
            WHERE c.userId = ?
        `).all(req.session.user.id);
        
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        res.render('cart', { 
            title: 'Cart', 
            items, 
            subtotal
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
    } catch (error) {
        console.error('Cart update error:', error);
    }
    
    res.redirect('/cart');
});

app.post('/cart/remove/:cartId', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    
    try {
        db.prepare('DELETE FROM cart WHERE id = ? AND userId = ?').run(req.params.cartId, req.session.user.id);
    } catch (error) {
        console.error('Cart remove error:', error);
    }
    
    res.redirect('/cart');
});

// ==================== CHECKOUT & COUPON SYSTEM ====================
app.get('/checkout', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    
    try {
        const items = db.prepare(`
            SELECT c.quantity, p.* FROM cart c
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
            couponCode: null
        });
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).send('Error loading checkout');
    }
});

app.post('/checkout/apply-coupon', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    
    const { code } = req.body;
    
    try {
        const coupon = db.prepare(`
            SELECT * FROM coupons 
            WHERE code = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
            AND (max_uses IS NULL OR used_count < max_uses)
        `).get(code);
        
        if (!coupon) {
            return res.json({ valid: false, error: 'Invalid or expired coupon' });
        }
        
        // Store in session
        req.session.coupon = coupon;
        
        res.json({ 
            valid: true, 
            discount: coupon.discount_value,
            type: coupon.discount_type
        });
    } catch (error) {
        console.error('Coupon error:', error);
        res.json({ valid: false, error: 'Error applying coupon' });
    }
});

app.post('/checkout/place-order', uploadProof.single('proof'), async (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    if (!req.file) return res.redirect('/checkout');
    
    const userId = req.session.user.id;
    
    try {
        const items = db.prepare(`
            SELECT c.quantity, p.* FROM cart c
            JOIN products p ON c.productId = p.id
            WHERE c.userId = ?
        `).all(userId);
        
        if (items.length === 0) return res.redirect('/shop');
        
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        let discount = 0;
        let couponCode = null;
        
        if (req.session.coupon) {
            const coupon = req.session.coupon;
            if (coupon.discount_type === 'percentage') {
                discount = subtotal * (coupon.discount_value / 100);
            } else {
                discount = coupon.discount_value;
            }
            
            // Update coupon usage
            db.prepare('UPDATE coupons SET used_count = used_count + 1 WHERE id = ?').run(coupon.id);
            couponCode = coupon.code;
            
            // Clear coupon from session
            delete req.session.coupon;
        }
        
        const total = Math.max(0, subtotal - discount);
        const filename = req.file.filename;
        
        const itemsJson = JSON.stringify(items.map(i => ({
            id: i.id,
            name: i.name,
            price: i.price,
            quantity: i.quantity
        })));
        
        const orderStmt = db.prepare(`
            INSERT INTO orders (userId, items, subtotal, discount, total, coupon, proof, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        `);
        
        const orderResult = orderStmt.run(userId, itemsJson, subtotal, discount, total, couponCode, filename);
        
        // Clear cart
        db.prepare('DELETE FROM cart WHERE userId = ?').run(userId);
        
        // Send payment log to Discord
        await sendLog('payment', {
            userId,
            username: req.session.user.username,
            items: items.map(i => `${i.quantity}x ${i.name}`).join(', '),
            total,
            proofFilename: filename,
            orderId: orderResult.lastInsertRowid
        });
        
        res.redirect('/history');
    } catch (error) {
        console.error('Order placement error:', error);
        res.status(500).send('Error placing order');
    }
});

// ==================== ORDER HISTORY ====================
app.get('/history', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/discord');
    
    try {
        const orders = db.prepare(`
            SELECT * FROM orders
            WHERE userId = ?
            ORDER BY created_at DESC
        `).all(req.session.user.id);
        
        // Parse items JSON for display
        orders.forEach(order => {
            try {
                order.itemsParsed = JSON.parse(order.items);
            } catch (e) {
                order.itemsParsed = [];
            }
        });
        
        res.render('history', { 
            title: 'Order History', 
            orders
        });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).send('Error loading history');
    }
});

// ==================== TERMS PAGE ====================
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

// Admin Dashboard
app.get('/admin', adminOnly, (req, res) => {
    try {
        // Get counts with error handling
        let usersCount = 0, productsCount = 0, ordersCount = 0, pendingCount = 0, approvedCount = 0, couponsCount = 0;
        
        try { usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count; } catch (e) {}
        try { productsCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count; } catch (e) {}
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
        
        // Parse items JSON for display
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
            section: 'dashboard'
        });
    } catch (error) {
        console.error('Admin error:', error);
        res.status(500).send('Error loading admin dashboard');
    }
});

// ==================== ADMIN PRODUCT MANAGEMENT ====================
app.get('/admin/products', adminOnly, (req, res) => {
    try {
        const products = db.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
        res.render('admin', { 
            title: 'Manage Products', 
            products,
            section: 'products'
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
        section: 'product-form'
    });
});

app.post('/admin/products/add', adminOnly, uploadProductImage.single('image'), (req, res) => {
    try {
        const { name, price, description, category, stock, featured } = req.body;
        const image = req.file ? `/product-images/${req.file.filename}` : null;
        
        const stmt = db.prepare(`
            INSERT INTO products (name, price, description, category, stock, featured, image)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        
        stmt.run(
            name, 
            parseFloat(price), 
            description, 
            category || 'general', 
            parseInt(stock) || 999, 
            featured ? 1 : 0,
            image
        );
        
        res.redirect('/admin/products');
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).send('Error adding product');
    }
});

app.get('/admin/products/edit/:id', adminOnly, (req, res) => {
    try {
        const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
        if (!product) return res.redirect('/admin/products');
        
        res.render('admin', { 
            title: 'Edit Product', 
            product,
            section: 'product-form'
        });
    } catch (error) {
        console.error('Edit product error:', error);
        res.status(500).send('Error loading product');
    }
});

app.post('/admin/products/edit/:id', adminOnly, uploadProductImage.single('image'), (req, res) => {
    try {
        const { name, price, description, category, stock, featured } = req.body;
        const id = req.params.id;
        
        let image = null;
        if (req.file) {
            image = `/product-images/${req.file.filename}`;
            
            // Delete old image if exists
            const old = db.prepare('SELECT image FROM products WHERE id = ?').get(id);
            if (old?.image) {
                const oldPath = path.join(__dirname, 'public', old.image);
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
        }
        
        if (image) {
            db.prepare(`
                UPDATE products SET name = ?, price = ?, description = ?, category = ?, stock = ?, featured = ?, image = ?
                WHERE id = ?
            `).run(name, parseFloat(price), description, category, parseInt(stock), featured ? 1 : 0, image, id);
        } else {
            db.prepare(`
                UPDATE products SET name = ?, price = ?, description = ?, category = ?, stock = ?, featured = ?
                WHERE id = ?
            `).run(name, parseFloat(price), description, category, parseInt(stock), featured ? 1 : 0, id);
        }
        
        res.redirect('/admin/products');
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).send('Error updating product');
    }
});

app.post('/admin/products/delete/:id', adminOnly, (req, res) => {
    try {
        const id = req.params.id;
        
        // Delete product image
        const product = db.prepare('SELECT image FROM products WHERE id = ?').get(id);
        if (product?.image) {
            const imagePath = path.join(__dirname, 'public', product.image);
            if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
        }
        
        db.prepare('DELETE FROM products WHERE id = ?').run(id);
        res.redirect('/admin/products');
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).send('Error deleting product');
    }
});

// ==================== ADMIN COUPON MANAGEMENT ====================
app.get('/admin/coupons', adminOnly, (req, res) => {
    try {
        const coupons = db.prepare('SELECT * FROM coupons ORDER BY created_at DESC').all();
        res.render('admin', { 
            title: 'Manage Coupons', 
            coupons,
            section: 'coupons'
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
        section: 'coupon-form'
    });
});

// Generate random coupon code
function generateCouponCode(prefix = '', length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = prefix ? prefix + '-' : '';
    for (let i = 0; i < length; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

app.post('/admin/coupons/generate', adminOnly, (req, res) => {
    try {
        const { 
            discount_type, 
            discount_value, 
            min_order, 
            max_uses, 
            expires_days,
            custom_code,
            code_prefix
        } = req.body;
        
        let code = custom_code;
        if (!code) {
            code = generateCouponCode(code_prefix, 8);
        }
        
        const expires_at = expires_days ? new Date(Date.now() + expires_days * 24 * 60 * 60 * 1000).toISOString() : null;
        
        const stmt = db.prepare(`
            INSERT INTO coupons (code, discount_type, discount_value, min_order, max_uses, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        
        stmt.run(
            code,
            discount_type,
            parseFloat(discount_value),
            parseFloat(min_order) || 0,
            parseInt(max_uses) || 1,
            expires_at
        );
        
        res.redirect('/admin/coupons');
    } catch (error) {
        console.error('Generate coupon error:', error);
        res.status(500).send('Error generating coupon');
    }
});

app.post('/admin/coupons/delete/:id', adminOnly, (req, res) => {
    try {
        db.prepare('DELETE FROM coupons WHERE id = ?').run(req.params.id);
        res.redirect('/admin/coupons');
    } catch (error) {
        console.error('Delete coupon error:', error);
        res.status(500).send('Error deleting coupon');
    }
});

// ==================== ADMIN ORDER MANAGEMENT ====================
app.get('/admin/orders', adminOnly, (req, res) => {
    try {
        const status = req.query.status || 'all';
        
        let query = `
            SELECT o.*, u.username FROM orders o
            JOIN users u ON o.userId = u.id
        `;
        const params = [];
        
        if (status !== 'all') {
            query += ' WHERE o.status = ?';
            params.push(status);
        }
        
        query += ' ORDER BY o.created_at DESC';
        
        const orders = params.length > 0 
            ? db.prepare(query).all(...params)
            : db.prepare(query).all();
        
        // Parse items JSON for display
        orders.forEach(order => {
            try {
                order.itemsParsed = JSON.parse(order.items);
                order.itemCount = order.itemsParsed.length;
            } catch (e) {
                order.itemCount = 0;
            }
        });
        
        res.render('admin', { 
            title: 'Manage Orders', 
            orders,
            currentStatus: status,
            section: 'orders'
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
        
        // Update status
        db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(action, orderId);
        
        // Get order details
        const order = db.prepare(`
            SELECT o.*, u.username, u.id as userId FROM orders o
            JOIN users u ON o.userId = u.id
            WHERE o.id = ?
        `).get(orderId);
        
        if (action === 'approved' && order) {
            // Give Discord role
            await giveRole(order.userId, config.discord.autoRoleId);
            
            // Parse items for log
            let itemsText = '';
            try {
                const items = JSON.parse(order.items);
                itemsText = items.map(i => `${i.quantity}x ${i.name}`).join(', ');
            } catch (e) {
                itemsText = order.items;
            }
            
            await sendLog('approved', {
                userId: order.userId,
                username: order.username,
                items: itemsText,
                orderId
            });
        }
        
        res.redirect('/admin/orders');
    } catch (error) {
        console.error('Order action error:', error);
        res.status(500).send('Error processing order');
    }
});

// ==================== API ENDPOINTS ====================
app.get('/api/cart/count', (req, res) => {
    if (!req.session.user) return res.json({ count: 0 });
    
    try {
        const count = db.prepare('SELECT COUNT(*) as count FROM cart WHERE userId = ?').get(req.session.user.id).count;
        res.json({ count });
    } catch (e) {
        res.json({ count: 0 });
    }
});

// ==================== 404 HANDLER ====================
app.use((req, res) => {
    res.status(404).render('404', { title: 'Page Not Found' });
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
║   🔥 IMPOSTER Network v2.0 – Fully Fixed
║   📊 Features: Cart • History • Terms • All Working
║   🗄️ Database: SQLite (Imposter.db)
║   © IMPOSTER Network – Dev Rick                          
╚══════════════════════════════════════════════════════════╝
        `);
    });
}).catch(err => {
    console.error('Failed to start bot:', err);
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
║   🔥 IMPOSTER Network v2.0 – Web Server Only
║   📊 Features: Cart • History • Terms • All Working
║   ⚠️ Discord Bot: Disconnected
║   © IMPOSTER Network – Dev Rick                          
╚══════════════════════════════════════════════════════════╝
        `);
    });
});
