// config.js – Central configuration
require('dotenv').config();

module.exports = {
    discord: {
        clientId: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        redirectUri: process.env.DISCORD_REDIRECT_URI,
        botToken: process.env.DISCORD_BOT_TOKEN,
        loginLogChannel: process.env.LOGIN_LOG_CHANNEL,
        paymentLogChannel: process.env.PAYMENT_LOG_CHANNEL,
        approvedLogChannel: process.env.APPROVED_LOG_CHANNEL,
        autoRoleId: process.env.AUTO_ROLE_ID
    },
    session: {
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false } // set true if using HTTPS
    },
    admin: {
        discordId: process.env.ADMIN_DISCORD_ID
    },
    server: {
        baseUrl: process.env.BASE_URL,
        port: process.env.PORT || 3000
    },
    upload: {
        maxSize: 5 * 1024 * 1024, // 5MB
        allowedTypes: ['image/png', 'image/jpeg', 'image/jpg']
    }
};
