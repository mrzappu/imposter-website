// test-discord.js - Test Discord bot connection and logs
require('dotenv').config();
const { initBot, sendLog, getBotStatus } = require('./bot');

async function testDiscord() {
    console.log('\n🔍 TESTING DISCORD BOT CONFIGURATION');
    console.log('=======================================\n');
    
    // Check environment variables
    console.log('📋 Environment Variables:');
    console.log(`DISCORD_BOT_TOKEN: ${process.env.DISCORD_BOT_TOKEN ? '✅ Set' : '❌ Missing'}`);
    console.log(`LOGIN_LOG_CHANNEL: ${process.env.LOGIN_LOG_CHANNEL ? '✅ Set' : '❌ Missing'}`);
    console.log(`PAYMENT_LOG_CHANNEL: ${process.env.PAYMENT_LOG_CHANNEL ? '✅ Set' : '❌ Missing'}`);
    console.log(`APPROVED_LOG_CHANNEL: ${process.env.APPROVED_LOG_CHANNEL ? '✅ Set' : '❌ Missing'}`);
    console.log(`AUTO_ROLE_ID: ${process.env.AUTO_ROLE_ID ? '✅ Set' : '❌ Missing'}`);
    
    // Initialize bot
    console.log('\n🤖 Initializing Discord bot...');
    const client = await initBot();
    
    if (!client) {
        console.error('❌ Failed to initialize bot');
        return;
    }
    
    // Wait for bot to be ready
    console.log('⏳ Waiting for bot to connect...');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    const status = getBotStatus();
    console.log('\n📊 Bot Status:');
    console.log(`   Connected: ${status.connected ? '✅ Yes' : '❌ No'}`);
    console.log(`   Bot Tag: ${status.botTag || 'N/A'}`);
    console.log(`   Servers: ${status.servers}`);
    
    if (!status.connected) {
        console.error('\n❌ Bot not connected. Check your token and try again.');
        return;
    }
    
    // Test sending logs
    console.log('\n📤 Sending test logs to all channels...');
    
    // Test login log
    console.log('\n1️⃣ Testing LOGIN log...');
    const loginResult = await sendLog('login', {
        userId: '123456789012345678',
        username: 'Test User',
        avatar: null
    });
    console.log(`   ${loginResult ? '✅' : '❌'} Login log ${loginResult ? 'sent' : 'failed'}`);
    
    // Test payment log
    console.log('\n2️⃣ Testing PAYMENT log...');
    const paymentResult = await sendLog('payment', {
        userId: '123456789012345678',
        username: 'Test User',
        avatar: null,
        items: '1x Test Product, 2x Another Product',
        total: 29.99,
        orderId: 9999
    });
    console.log(`   ${paymentResult ? '✅' : '❌'} Payment log ${paymentResult ? 'sent' : 'failed'}`);
    
    // Test approval log
    console.log('\n3️⃣ Testing APPROVED log...');
    const approvedResult = await sendLog('approved', {
        userId: '123456789012345678',
        username: 'Test User',
        avatar: null,
        items: '1x Test Product, 2x Another Product',
        orderId: 9999
    });
    console.log(`   ${approvedResult ? '✅' : '❌'} Approval log ${approvedResult ? 'sent' : 'failed'}`);
    
    console.log('\n✅ Test complete! Check your Discord channels for the test messages.');
    console.log('\n🛑 Exiting in 10 seconds...');
    
    setTimeout(() => {
        console.log('\n👋 Goodbye!');
        process.exit(0);
    }, 10000);
}

testDiscord().catch(console.error);
