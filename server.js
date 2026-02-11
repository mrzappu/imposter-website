const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");

const app = express();
const db = new sqlite3.Database("./imposter.db");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(session({
    secret: "imposterSecretKey",
    resave: false,
    saveUninitialized: true
}));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT DEFAULT 'user'
    )`);
});

// Default Admin
db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
        db.run("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')");
    }
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password]);
    res.redirect("/login.html");
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username=? AND password=?", [username, password], (err, user) => {
        if (user) {
            req.session.user = user;
            if (user.role === "admin") {
                res.redirect("/admin.html");
            } else {
                res.redirect("/shop.html");
            }
        } else {
            res.send("Invalid Login");
        }
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
