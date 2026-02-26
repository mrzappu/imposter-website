// bot.js – Discord bot for logging and auto-role with FIXED connection
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const config = require('./config');
const path = require('path');
const fs = require('fs');

let client = null;
let isReady = false;

async function initBot() {
    console.log('🤖 Initializing Discord bot...');
    
    // Check if token exists
    if (!config.discord.botToken) {
        console.error('❌ CRITICAL: DISCORD_BOT_TOKEN is missing from environment variables!');
        console.error('   Please check your .env file or Render environment variables.');
        return null;
    }
    
    // Log token preview (safely)
    const tokenPreview = config.discord.botToken.substring(0, 5) + '...' + config.discord.botToken.substring(config.discord.botToken.length - 5);
    console.log(`🔑 Token loaded: ${tokenPreview} (length: ${config.discord.botToken.length})`);
    
    // Check token format - Discord tokens are typically 70+ characters
    if (config.discord.botToken.length < 50) {
        console.warn('⚠️ Warning: Token seems too short. Discord tokens are usually 70+ characters.');
    }

    client = new Client({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.MessageContent
        ]
    });

    client.once('ready', () => {
        console.log('✅ Discord Bot connected successfully!');
        console.log(`🤖 Bot Tag: ${client.user.tag}`);
        console.log(`🆔 Bot ID: ${client.user.id}`);
        console.log(`📊 Servers: ${client.guilds.cache.size}`);
        
        // Log which servers the bot is in
        client.guilds.cache.forEach(guild => {
            console.log(`   - ${guild.name} (${guild.id})`);
        });
        
        // Log which channels are configured
        console.log('📋 Configured Channels:');
        console.log(`   - Login Log: ${config.discord.loginLogChannel || 'Not set'}`);
        console.log(`   - Payment Log: ${config.discord.paymentLogChannel || 'Not set'}`);
        console.log(`   - Approved Log: ${config.discord.approvedLogChannel || 'Not set'}`);
        console.log(`   - Auto Role ID: ${config.discord.autoRoleId || 'Not set'}`);
        
        // Verify channels exist
        verifyChannels();
        isReady = true;
    });

    client.on('error', (error) => {
        console.error('❌ Discord client error:', error.message);
        if (error.code === 'TokenInvalid') {
            console.error('   → Your bot token is invalid! Please reset it in Discord Developer Portal.');
            console.error('   → Go to: https://discord.com/developers/applications');
        } else if (error.code === 'DisallowedIntent') {
            console.error('   → You need to enable Privileged Gateway Intents in Discord Developer Portal.');
            console.error('   → Go to Bot tab → Enable: Presence Intent, Server Members Intent, Message Content Intent');
        }
        isReady = false;
    });

    try {
        console.log('🔄 Attempting to login to Discord...');
        await client.login(config.discord.botToken);
        console.log('✅ Login successful!');
    } catch (error) {
        console.error('❌ Failed to login to Discord:', error.message);
        
        // Specific error handling
        if (error.message.includes('An invalid token was provided')) {
            console.error('   → The token is invalid. Please reset it in Discord Developer Portal.');
            console.error('   → Steps:');
            console.error('     1. Go to https://discord.com/developers/applications');
            console.error('     2. Select your bot application');
            console.error('     3. Go to "Bot" tab');
            console.error('     4. Click "Reset Token"');
            console.error('     5. Copy the NEW token');
            console.error('     6. Update your .env file and Render environment variables');
        } else if (error.message.includes('Privileged intent')) {
            console.error('   → You need to enable Privileged Gateway Intents:');
            console.error('     1. Go to Discord Developer Portal → Bot tab');
            console.error('     2. Scroll down to "Privileged Gateway Intents"');
            console.error('     3. Enable ALL THREE:');
            console.error('        - Presence Intent');
            console.error('        - Server Members Intent');
            console.error('        - Message Content Intent');
        }
        return null;
    }

    return client;
}

async function verifyChannels() {
    if (!client || !isReady) return;

    const channels = [
        { name: 'Login Log', id: config.discord.loginLogChannel },
        { name: 'Payment Log', id: config.discord.paymentLogChannel },
        { name: 'Approved Log', id: config.discord.approvedLogChannel }
    ];

    for (const channel of channels) {
        if (!channel.id) {
            console.warn(`⚠️ ${channel.name} channel ID not set`);
            continue;
        }

        try {
            const ch = await client.channels.fetch(channel.id);
            console.log(`✅ ${channel.name} channel found: #${ch.name} (${ch.id})`);
        } catch (error) {
            console.error(`❌ ${channel.name} channel not found (ID: ${channel.id})`);
            if (error.code === 50001) {
                console.error('   → Bot lacks permissions to view this channel');
            } else if (error.code === 10003) {
                console.error('   → Channel does not exist');
            }
        }
    }
}

async function sendLog(type, data) {
    if (!client || !isReady) {
        console.error(`❌ Cannot send ${type} log - Discord bot not ready`);
        return false;
    }

    let channelId;
    let embed;
    let files = [];

    switch (type) {
        case 'login':
            channelId = config.discord.loginLogChannel;
            if (!channelId) {
                console.error('❌ LOGIN_LOG_CHANNEL not set');
                return false;
            }

            embed = new EmbedBuilder()
                .setTitle('🔐 New Login')
                .setColor(0x00ff00)
                .setThumbnail(data.avatar || 'https://cdn.discordapp.com/embed/avatars/0.png')
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'User ID', value: data.userId, inline: true },
                    { name: 'Time', value: new Date().toLocaleString(), inline: false }
                )
                .setFooter({ text: `IMPOSTER Network` })
                .setTimestamp();
            break;

        case 'payment':
            channelId = config.discord.paymentLogChannel;
            if (!channelId) {
                console.error('❌ PAYMENT_LOG_CHANNEL not set');
                return false;
            }

            embed = new EmbedBuilder()
                .setTitle('💰 Payment Proof Uploaded')
                .setColor(0xffaa00)
                .setThumbnail(data.avatar || 'https://cdn.discordapp.com/embed/avatars/0.png')
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'Order ID', value: `#${data.orderId}`, inline: true },
                    { name: 'Items', value: data.items || 'N/A', inline: false },
                    { name: 'Total', value: `₹${data.total?.toFixed(2) || '0.00'}`, inline: true },
                    { name: 'Time', value: new Date().toLocaleString(), inline: false }
                )
                .setFooter({ text: `IMPOSTER Network` })
                .setTimestamp();

            if (data.proofFilename) {
                const proofPath = path.join(__dirname, 'public/uploads', data.proofFilename);
                if (fs.existsSync(proofPath)) {
                    files.push({
                        attachment: proofPath,
                        name: data.proofFilename
                    });
                }
            }
            break;

        case 'approved':
            channelId = config.discord.approvedLogChannel;
            if (!channelId) {
                console.error('❌ APPROVED_LOG_CHANNEL not set');
                return false;
            }

            embed = new EmbedBuilder()
                .setTitle('✅ Payment Approved')
                .setColor(0x00ff00)
                .setThumbnail(data.avatar || 'https://cdn.discordapp.com/embed/avatars/0.png')
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'Order ID', value: `#${data.orderId}`, inline: true },
                    { name: 'Items', value: data.items || 'N/A', inline: false },
                    { name: 'Role Given', value: config.discord.autoRoleId ? `<@&${config.discord.autoRoleId}>` : 'Not Set', inline: true },
                    { name: 'Time', value: new Date().toLocaleString(), inline: false }
                )
                .setFooter({ text: `IMPOSTER Network` })
                .setTimestamp();
            break;
    }

    try {
        const channel = await client.channels.fetch(channelId);
        if (files.length > 0) {
            await channel.send({ embeds: [embed], files });
            console.log(`✅ ${type} log sent with attachment to #${channel.name}`);
        } else {
            await channel.send({ embeds: [embed] });
            console.log(`✅ ${type} log sent to #${channel.name}`);
        }
        return true;
    } catch (error) {
        console.error(`❌ Failed to send ${type} log:`, error.message);
        if (error.code === 50001) {
            console.error('   → Bot lacks Send Messages permission in that channel');
        } else if (error.code === 50013) {
            console.error('   → Bot missing permissions: Send Messages, Embed Links, Attach Files');
        }
        return false;
    }
}

async function giveRole(userId, roleId) {
    if (!client || !isReady) {
        console.error('❌ Cannot give role - Discord bot not ready');
        return false;
    }

    if (!roleId) {
        console.error('❌ AUTO_ROLE_ID not set');
        return false;
    }

    try {
        for (const guild of client.guilds.cache.values()) {
            try {
                const member = await guild.members.fetch(userId).catch(() => null);
                if (member) {
                    const role = await guild.roles.fetch(roleId).catch(() => null);
                    if (role) {
                        await member.roles.add(role);
                        console.log(`✅ Role ${role.name} given to ${member.user.tag}`);
                        
                        // Send confirmation DM
                        try {
                            await member.send(`✅ Your payment has been approved! You have received the **${role.name}** role in **${guild.name}**.`);
                        } catch (dmError) {
                            console.log(`⚠️ Could not DM user (DMs disabled)`);
                        }
                        return true;
                    } else {
                        console.error(`❌ Role ${roleId} not found in guild ${guild.name}`);
                    }
                }
            } catch (err) {
                console.error(`Error checking guild ${guild.name}:`, err.message);
            }
        }
        console.error(`❌ Could not give role to user ${userId} - user not found in any guild`);
        return false;
    } catch (error) {
        console.error('Role error:', error.message);
        return false;
    }
}

function getBotStatus() {
    return {
        connected: isReady,
        botTag: client?.user?.tag || null,
        botId: client?.user?.id || null,
        servers: client?.guilds.cache.size || 0
    };
}

module.exports = { initBot, sendLog, giveRole, getBotStatus };
