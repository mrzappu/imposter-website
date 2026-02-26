// test-bot.js - Test your Discord bot configuration locally
require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');

async function testBot() {
    console.log('\n🔍 TESTING DISCORD BOT CONFIGURATION');
    console.log('=====================================\n');
    
    const token = process.env.DISCORD_BOT_TOKEN;
    
    if (!token) {
        console.error('❌ DISCORD_BOT_TOKEN not found in .env file!');
        console.log('\n📝 Please add your token to .env:');
        console.log('DISCORD_BOT_TOKEN=your_token_here');
        return;
    }
    
    console.log(`🔑 Token found (length: ${token.length})`);
    console.log(`🔑 Token preview: ${token.substring(0, 10)}...${token.substring(token.length - 10)}`);
    
    // Check token format
    if (token.length < 50) {
        console.warn('⚠️ Warning: Token seems too short. Discord tokens are usually 70+ characters.');
    }
    
    if (!token.includes('.') || token.split('.').length !== 3) {
        console.warn('⚠️ Warning: Token format looks incorrect. Should be three parts separated by dots.');
    }
    
    console.log('\n🔄 Attempting to connect to Discord...');
    
    const client = new Client({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.MessageContent
        ]
    });
    
    client.once('ready', () => {
        console.log('✅ SUCCESS! Bot connected to Discord!');
        console.log(`🤖 Bot Tag: ${client.user.tag}`);
        console.log(`🆔 Bot ID: ${client.user.id}`);
        console.log(`📊 Servers: ${client.guilds.cache.size}`);
        
        client.guilds.cache.forEach(guild => {
            console.log(`   - ${guild.name} (${guild.id})`);
        });
        
        console.log('\n✅ Test complete! Your bot token is valid.');
        process.exit(0);
    });
    
    client.on('error', (error) => {
        console.error('❌ Connection error:', error.message);
        
        if (error.message.includes('An invalid token was provided')) {
            console.error('\n🔧 FIX: Your token is INVALID. Please reset it in Discord Developer Portal:');
            console.error('   1. Go to https://discord.com/developers/applications');
            console.error('   2. Select your bot application');
            console.error('   3. Go to "Bot" tab');
            console.error('   4. Click "Reset Token"');
            console.error('   5. Copy the NEW token');
            console.error('   6. Update your .env file');
        } else if (error.message.includes('Privileged intent')) {
            console.error('\n🔧 FIX: You need to enable Privileged Gateway Intents:');
            console.error('   1. Go to Discord Developer Portal → Bot tab');
            console.error('   2. Scroll to "Privileged Gateway Intents"');
            console.error('   3. Enable ALL THREE:');
            console.error('      - Presence Intent');
            console.error('      - Server Members Intent');
            console.error('      - Message Content Intent');
        }
        
        process.exit(1);
    });
    
    try {
        await client.login(token);
    } catch (error) {
        console.error('❌ Login failed:', error.message);
        process.exit(1);
    }
    
    // Timeout after 10 seconds
    setTimeout(() => {
        console.error('\n❌ Timeout: Bot didn\'t connect within 10 seconds');
        process.exit(1);
    }, 10000);
}

testBot();
