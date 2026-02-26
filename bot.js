// bot.js – Discord bot for logging and auto-role
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const config = require('./config');
const path = require('path');

let client = null;

async function initBot() {
    client = new Client({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers
        ]
    });

    client.once('ready', () => {
        console.log('✅ Discord Bot connected');
    });

    client.on('error', console.error);

    await client.login(config.discord.botToken);
    return client;
}

async function sendLog(type, data) {
    if (!client) return;

    let channelId;
    let embed;

    switch (type) {
        case 'login':
            channelId = config.discord.loginLogChannel;
            embed = new EmbedBuilder()
                .setTitle('🔐 New Login')
                .setColor(0x00ff00)
                .setThumbnail(data.avatar)
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'ID', value: data.userId, inline: true }
                )
                .setTimestamp();
            break;

        case 'payment':
            channelId = config.discord.paymentLogChannel;
            embed = new EmbedBuilder()
                .setTitle('💰 Payment Proof Uploaded')
                .setColor(0xffaa00)
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'Products', value: data.productNames, inline: false },
                    { name: 'Total', value: `$${data.total}`, inline: true },
                    { name: 'Order ID', value: `#${data.orderId}`, inline: true }
                )
                .setImage(`attachment://${data.proofFilename}`)
                .setTimestamp();
            break;

        case 'approved':
            channelId = config.discord.approvedLogChannel;
            embed = new EmbedBuilder()
                .setTitle('✅ Payment Approved')
                .setColor(0x00ff00)
                .addFields(
                    { name: 'User', value: `<@${data.userId}>`, inline: true },
                    { name: 'Username', value: data.username, inline: true },
                    { name: 'Product', value: data.productName, inline: false },
                    { name: 'Order ID', value: `#${data.orderId}`, inline: true },
                    { name: 'Role', value: `<@&${config.discord.autoRoleId}>`, inline: true }
                )
                .setTimestamp();
            break;

        default:
            return;
    }

    try {
        const channel = await client.channels.fetch(channelId);
        if (type === 'payment') {
            const filePath = path.join(__dirname, 'public/uploads', data.proofFilename);
            await channel.send({ embeds: [embed], files: [filePath] });
        } else {
            await channel.send({ embeds: [embed] });
        }
    } catch (err) {
        console.error('Log error:', err);
    }
}

async function giveRole(userId, roleId) {
    if (!client) return;

    try {
        // Find guild where bot is and role exists
        for (const guild of client.guilds.cache.values()) {
            if (guild.roles.cache.has(roleId)) {
                const member = await guild.members.fetch(userId).catch(() => null);
                if (member) {
                    await member.roles.add(roleId);
                    console.log(`✅ Role given to ${userId}`);
                    return;
                }
            }
        }
        console.log(`⚠️ Could not give role to ${userId} – user not in guild or role missing`);
    } catch (err) {
        console.error('Role error:', err);
    }
}

module.exports = { initBot, sendLog, giveRole };
