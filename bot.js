// bot.js – Discord bot for logging and auto-role
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const config = require('./config');
const path = require('path');
const fs = require('fs');

let client = null;
let isReady = false;

async function initBot() {
    if (!config.discord.botToken) {
        console.error('❌ DISCORD_BOT_TOKEN not set in environment variables');
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
        console.error('Discord client error:', error);
        isReady = false;
    });

    try {
        await client.login(config.discord.botToken);
    } catch (error) {
        console.error('❌ Failed to login to Discord:', error.message);
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
                    { name: 'Total', value: `$${data.total?.toFixed(2) || '0.00'}`, inline: true },
                    { name: 'Time', value: new Date().toLocaleString(), inline: false }
                )
                .setFooter({ text: `IMPOSTER Network` })
                .setTimestamp();

            // Attach proof image if available
            if (data.proofFilename) {
                const proofPath = path.join(__dirname, 'public/uploads', data.proofFilename);
                if (fs.existsSync(proofPath)) {
                    files.push({
                        attachment: proofPath,
                        name: data.proofFilename
                    });
                    console.log(`📎 Attaching proof file: ${data.proofFilename}`);
                } else {
                    console.warn(`⚠️ Proof file not found: ${proofPath}`);
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

        default:
            console.error(`❌ Unknown log type: ${type}`);
            return false;
    }

    try {
        const channel = await client.channels.fetch(channelId);
        
        if (!channel) {
            console.error(`❌ Channel not found: ${channelId}`);
            return false;
        }

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
        
        // Specific error handling
        if (error.code === 50001) {
            console.error('   → Bot lacks permissions in that channel');
            console.error('   → Required: Send Messages, Embed Links, Attach Files');
        } else if (error.code === 10003) {
            console.error('   → Channel not found');
        } else if (error.code === 50013) {
            console.error('   → Bot missing permissions');
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
        // Find the guild where the bot and user are
        for (const guild of client.guilds.cache.values()) {
            try {
                const member = await guild.members.fetch(userId).catch(() => null);
                if (member) {
                    const role = await guild.roles.fetch(roleId).catch(() => null);
                    if (role) {
                        await member.roles.add(role);
                        console.log(`✅ Role ${role.name} given to ${member.user.tag}`);
                        
                        // Send confirmation DM to user
                        try {
                            await member.send(`✅ Your payment has been approved! You have received the **${role.name}** role in **${guild.name}**.`);
                            console.log(`📨 DM sent to ${member.user.tag}`);
                        } catch (dmError) {
                            console.log(`⚠️ Could not DM user ${member.user.tag} (DMs disabled)`);
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
