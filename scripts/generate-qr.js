const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const upiId = process.env.UPI_ID || '8078794395@fam';
const paymentNote = process.env.PAYMENT_NOTE || 'IMPOSTER Network Payment';
const defaultAmount = process.env.DEFAULT_AMOUNT || '19.99';

const upiData = `upi://pay?pa=${encodeURIComponent(upiId)}&pn=IMPOSTER&am=${defaultAmount}&cu=INR&tn=${encodeURIComponent(paymentNote)}`;
const outputPath = path.join(__dirname, '../public/qr.png');

if (!fs.existsSync(path.join(__dirname, '../public'))) {
    fs.mkdirSync(path.join(__dirname, '../public'), { recursive: true });
}

QRCode.toFile(outputPath, upiData, { width: 400, margin: 2 }, (err) => {
    if (err) console.error('❌ Error generating QR:', err);
    else console.log('✅ UPI QR Code generated at:', outputPath);
});
