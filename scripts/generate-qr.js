// scripts/generate-qr.js - Generate UPI QR code for payment
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// UPI payment details from .env
const upiId = process.env.UPI_ID || '8078794395@fam';
const paymentNote = process.env.PAYMENT_NOTE || 'IMPOSTER Network Payment';
const defaultAmount = process.env.DEFAULT_AMOUNT || '19.99';

// Create UPI QR code data (standard UPI format)
// Format: upi://pay?pa=UPI_ID&pn=RecipientName&am=Amount&cu=INR&tn=Note
const upiData = `upi://pay?pa=${encodeURIComponent(upiId)}&pn=IMPOSTER%20Network&am=${defaultAmount}&cu=INR&tn=${encodeURIComponent(paymentNote)}`;

// Output path
const outputPath = path.join(__dirname, '../public/qr.png');

// Ensure public directory exists
const publicDir = path.join(__dirname, '../public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
}

// Generate QR code
QRCode.toFile(outputPath, upiData, {
    color: {
        dark: '#000000',
        light: '#ffffff'
    },
    width: 400,
    margin: 2,
    errorCorrectionLevel: 'H'
}, (err) => {
    if (err) {
        console.error('❌ Error generating QR:', err);
    } else {
        console.log('✅ UPI QR Code generated successfully!');
        console.log(`📁 Location: ${outputPath}`);
        console.log('📱 UPI Payment Details:');
        console.log(`   - UPI ID: ${upiId}`);
        console.log(`   - Amount: ₹${defaultAmount}`);
        console.log(`   - Note: ${paymentNote}`);
        console.log('\n📊 QR Data encoded:', upiData);
        
        // Also save payment details as JSON for reference
        const detailsPath = path.join(__dirname, '../public/upi-details.json');
        fs.writeFileSync(detailsPath, JSON.stringify({
            upiId,
            amount: defaultAmount,
            note: paymentNote,
            qrData: upiData
        }, null, 2));
        console.log(`📄 UPI details saved to: ${detailsPath}`);
    }
});
