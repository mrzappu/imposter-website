// bot.js – Discord bot for logging and auto-role
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const config = require('./config');
const path = require('path');
const fs = require('fs');

let client = null;
let isReady = false;

async function initBot() {
    console.log('🤖 Initializing Discord bot...');
    
    if (!config.discord.botToken) {
        console.error('❌ DISCORD_BOT_TOKEN missing');
        return null;
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
        console.log('✅ Discord Bot connected successfully');
        console.log(`🤖 Bot Tag: ${client.user.tag}`);
        console.log(`📊 Servers: ${client.guilds.cache.size}`);
        
        console.log('📋 Configured Channels:');
        console.log(`   - Login Log: ${config.discord.loginLogChannel || 'Not set'}`);
        console.log(`   - Payment Log: ${config.discord.paymentLogChannel || 'Not set'}`);
        console.log(`   - Approved Log: ${config.discord.approvedLogChannel || 'Not set'}`);
        console.log(`   - Auto Role ID: ${config.discord.autoRoleId || 'Not set'}`);
        
        verifyChannels();
        isReady = true;
    });

    client.on('error', (error) => {
        console.error('❌ Discord client error:', error.message);
        isReady = false;
    });

    try {
        await client.login(config.discord.botToken);
        console.log('✅ Bot login successful');
    } catch (error) {
        console.error('❌ Failed to login:', error.message);
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
            console.log(`✅ ${channel.name} channel found: #${ch.name}`);
        } catch (error) {
            console.error(`❌ ${channel.name} channel not found (ID: ${channel.id})`);
        }
    }
}

async function sendLog(type, data) {
    if (!client || !isReady) {
        return false;
    }

    let channelId;
    let embed;
    let files = [];

    switch (type) {
        case 'login':
            channelId = config.discord.loginLogChannel;
            if (!channelId) return false;

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
            if (!channelId) return false;

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
                    files.push({ attachment: proofPath, name: data.proofFilename });
                }
            }
            break;

        case 'approved':
            channelId = config.discord.approvedLogChannel;
            if (!channelId) return false;

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
        } else {
            await channel.send({ embeds: [embed] });
        }
        return true;
    } catch (error) {
        return false;
    }
}

async function giveRole(userId, roleId) {
    if (!client || !isReady) return false;
    if (!roleId) return false;

    try {
        for (const guild of client.guilds.cache.values()) {
            try {
                const member = await guild.members.fetch(userId).catch(() => null);
                if (member) {
                    const role = await guild.roles.fetch(roleId).catch(() => null);
                    if (role) {
                        await member.roles.add(role);
                        console.log(`✅ Role given to ${member.user.tag}`);
                        return true;
                    }
                }
            } catch (err) {}
        }
        return false;
    } catch (error) {
        return false;
    }
}

function getBotStatus() {
    return {
        connected: isReady,
        botTag: client?.user?.tag || null,
        servers: client?.guilds.cache.size || 0
    };
}

module.exports = { initBot, sendLog, giveRole, getBotStatus };
