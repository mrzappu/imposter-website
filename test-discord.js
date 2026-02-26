require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');

async function testBot() {
    console.log('\n🔍 TESTING DISCORD BOT...\n');
    
    const token = process.env.DISCORD_BOT_TOKEN;
    if (!token) {
        console.error('❌ DISCORD_BOT_TOKEN not found');
        return;
    }
    
    console.log(`🔑 Token length: ${token.length}`);
    
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });
    
    client.once('ready', () => {
        console.log('✅ Bot connected successfully!');
        console.log(`🤖 Bot Tag: ${client.user.tag}`);
        console.log(`📊 Servers: ${client.guilds.cache.size}`);
        client.destroy();
    });
    
    client.on('error', (err) => console.error('❌ Error:', err.message));
    
    try {
        await client.login(token);
        setTimeout(() => {
            console.log('⏳ Waiting for connection...');
        }, 5000);
    } catch (err) {
        console.error('❌ Login failed:', err.message);
    }
}

testBot();
