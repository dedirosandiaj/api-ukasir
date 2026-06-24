import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import { getConfig } from '../../utils/config';

// @ts-ignore - midtrans-client doesn't have types
import midtransClient from 'midtrans-client';

dotenv.config();

// Dynamic Midtrans Snap API Constructor
const getMidtransSnap = async () => {
    const serverKey = await getConfig('MIDTRANS_SERVER_KEY');
    const clientKey = await getConfig('MIDTRANS_CLIENT_KEY');
    const isProduction = await getConfig('MIDTRANS_IS_PRODUCTION') === 'true';
    return new midtransClient.Snap({
        isProduction,
        serverKey,
        clientKey
    });
};

// Dynamic Nodemailer Constructor
const getSmtpTransporter = async () => {
    const host = await getConfig('SMTP_HOST');
    const port = parseInt(await getConfig('SMTP_PORT', '465'));
    const user = await getConfig('SMTP_USER');
    const pass = await getConfig('SMTP_PASSWORD');
    return nodemailer.createTransport({
        host,
        port,
        secure: true, // true for 465
        auth: {
            user,
            pass
        },
        tls: {
            rejectUnauthorized: false
        }
    });
};

const router = Router();

// Helper function to send payment email
const sendPaymentEmail = async (email: string, name: string, merchantName: string, paymentUrl: string, amount: number, packageName: string, activationLink?: string) => {
    try {
        const smtpFrom = await getConfig('SMTP_FROM', 'Ukasir <noreply@ukasir.id>');
        const mailOptions = {
            from: smtpFrom,
            to: email,
            subject: 'Complete Your Ukasir Payment',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #2563eb;">Welcome to Ukasir!</h2>
                    <p>Thank you for registering. Please complete your payment to activate your account.</p>
                    
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Account Details:</h3>
                        <p style="margin: 5px 0;"><strong>Name:</strong> ${name}</p>
                        <p style="margin: 5px 0;"><strong>Merchant:</strong> ${merchantName}</p>
                    </div>
                    
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Package Details:</h3>
                        <p style="margin: 5px 0;"><strong>Package:</strong> ${packageName.charAt(0).toUpperCase() + packageName.slice(1)}</p>
                        <p style="margin: 5px 0;"><strong>Amount:</strong> Rp ${amount.toLocaleString('id-ID')}</p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${paymentUrl}" 
                           style="background: #2563eb; color: white; padding: 15px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                            Pay Now
                        </a>
                    </div>

                    ${activationLink ? `
                    <div style="background: #f0fdf4; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #16a34a;">
                        <h3 style="margin: 0 0 10px 0; color: #166534;">Aktivasi Akun (Setelah Pembayaran):</h3>
                        <p style="margin: 5px 0; font-size: 14px; color: #374151;">Setelah menyelesaikan pembayaran, Anda dapat mengaktifkan akun Anda secara manual menggunakan link berikut:</p>
                        <p style="margin: 10px 0; text-align: center;"><a href="${activationLink}" style="background: #16a34a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Aktifkan Akun Saya</a></p>
                    </div>
                    ` : ''}
                    
                    <p style="color: #6b7280; font-size: 14px;">This payment link will expire in 24 hours.</p>
                    <p style="color: #6b7280; font-size: 14px;">If you have any questions, please contact our support team.</p>
                    
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;"/>
                    <p style="color: #9ca3af; font-size: 12px; text-align: center;">© 2026 Ukasir. All rights reserved.</p>
                </div>
            `
        };

        const transporter = await getSmtpTransporter();
        await transporter.sendMail(mailOptions);
        console.log('Payment email sent to:', email);
    } catch (error) {
        console.error('Failed to send payment email:', error);
    }
};

// Helper function to send payment success email with token
const sendPaymentSuccessEmail = async (email: string, name: string, merchantName: string, token: string, packageName: string, activationLink?: string) => {
    try {
        const smtpFrom = await getConfig('SMTP_FROM', 'Ukasir <noreply@ukasir.id>');
        const isTrial = packageName === 'trial';
        const mailOptions = {
            from: smtpFrom,
            to: email,
            subject: isTrial ? 'Welcome to Ukasir - Your Trial Token' : 'Payment Successful - Your Ukasir Token',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: ${isTrial ? '#2563eb' : '#10b981'};">${isTrial ? '🎉 Welcome to Ukasir!' : '🎉 Payment Successful!'}</h2>
                    <p>${isTrial ? 'Thank you for registering. Your Ukasir account has been created!' : 'Thank you for your payment. Your Ukasir account is now active!'}</p>
                    
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Account Details:</h3>
                        <p style="margin: 5px 0;"><strong>Name:</strong> ${name}</p>
                        <p style="margin: 5px 0;"><strong>Merchant:</strong> ${merchantName}</p>
                    </div>

                    ${activationLink ? `
                    <div style="background: #e0f2fe; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #0284c7;">
                        <h3 style="margin: 0 0 10px 0; color: #0369a1;">${isTrial ? 'Aktivasi Akun Anda:' : 'Aktivasi Akun (Setelah Pembayaran):'}</h3>
                        <p style="margin: 5px 0; font-size: 14px; color: #334155;">${isTrial ? 'Silakan aktifkan token Anda terlebih dahulu dengan mengklik tombol di bawah ini:' : 'Setelah menyelesaikan pembayaran, Anda dapat mengaktifkan akun Anda secara manual menggunakan link berikut:'}</p>
                        <div style="text-align: center; margin: 15px 0;">
                            <a href="${activationLink}" 
                               style="background: #0284c7; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                                Aktifkan Akun
                            </a>
                        </div>
                    </div>
                    ` : ''}
                    
                    <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
                        <h3 style="margin: 0 0 10px 0;">Your Activation Token:</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #2563eb; letter-spacing: 2px; margin: 10px 0;">${token}</p>
                        <p style="margin: 5px 0; color: #6b7280; font-size: 14px;">Package: ${packageName.charAt(0).toUpperCase() + packageName.slice(1)}</p>
                    </div>
                    
                    <div style="background: #dbeafe; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Next Steps:</h3>
                        <ol style="margin: 10px 0; padding-left: 20px;">
                            ${activationLink ? '<li>Klik tombol "Aktifkan Akun" di atas</li>' : ''}
                            <li>Open Ukasir app</li>
                            <li>Enter your token number</li>
                            <li>Start using Ukasir!</li>
                        </ol>
                    </div>
                    
                    <p style="color: #6b7280; font-size: 14px;">Please keep this token safe and do not share it with anyone.</p>
                    <p style="color: #6b7280; font-size: 14px;">If you have any questions, please contact our support team.</p>
                    
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;"/>
                    <p style="color: #9ca3af; font-size: 12px; text-align: center;">© 2026 Ukasir. All rights reserved.</p>
                </div>
            `
        };

        const transporter = await getSmtpTransporter();
        await transporter.sendMail(mailOptions);
        console.log('Payment success email sent to:', email);
    } catch (error) {
        console.error('Failed to send payment success email:', error);
    }
};

// Helper function to render a premium activation page
const renderActivationPage = (success: boolean, message: string, exclusiveMerchant?: number | null): string => {
    return `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${success ? 'Aktivasi Berhasil' : 'Aktivasi Gagal'} - Ukasir</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background: radial-gradient(circle at top right, #f5f3ff, #e0e7ff);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #1e1b4b;
        }
        .card {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.4);
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(99, 102, 241, 0.1);
            max-width: 480px;
            width: 100%;
            padding: 40px;
            text-align: center;
            animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .icon-wrapper {
            width: 96px;
            height: 96px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 48px;
            animation: scaleIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        @keyframes scaleIn {
            from {
                transform: scale(0);
            }
            to {
                transform: scale(1);
            }
        }
        .success-icon {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            box-shadow: 0 10px 20px rgba(16, 185, 129, 0.2);
        }
        .error-icon {
            background: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
            color: white;
            box-shadow: 0 10px 20px rgba(244, 63, 94, 0.2);
        }
        h1 {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 16px;
            background: linear-gradient(to right, #4f46e5, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            color: #4b5563;
            margin-bottom: 32px;
        }
        .btn {
            display: inline-block;
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%);
            color: white;
            text-decoration: none;
            border-radius: 14px;
            font-weight: 600;
            font-size: 16px;
            box-shadow: 0 10px 20px rgba(79, 70, 229, 0.25);
            transition: all 0.3s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 25px rgba(79, 70, 229, 0.35);
        }
        .btn:active {
            transform: translateY(0);
        }
        .footer {
            margin-top: 32px;
            font-size: 13px;
            color: #9ca3af;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-wrapper ${success ? 'success-icon' : 'error-icon'}">
            ${success ? '✓' : '✕'}
        </div>
        <h1>${success ? 'Aktivasi Berhasil' : 'Aktivasi Gagal'}</h1>
        <p style="margin-bottom: 24px;">${message}</p>
        ${success && exclusiveMerchant ? `
        <div style="background: linear-gradient(135deg, #fef3c7 0%, #fffbeb 100%); border: 1px dashed #f59e0b; padding: 16px; border-radius: 16px; margin-bottom: 28px; display: flex; align-items: center; justify-content: center; gap: 8px; text-align: left; box-shadow: 0 4px 10px rgba(245, 158, 11, 0.08);">
            <span style="font-size: 24px;">👑</span>
            <span style="font-size: 14px; font-weight: 600; color: #b45309; line-height: 1.4;">
                Selamat, Anda masuk dalam merchant eksklusif urutan <strong>#${exclusiveMerchant}</strong> dari 100!
            </span>
        </div>
        ` : ''}
        <a href="ukasir://" class="btn">Buka Aplikasi Ukasir</a>
        <div class="footer">
            &copy; 2026 Ukasir. All rights reserved.
        </div>
    </div>
</body>
</html>
    `;
};


// Input sanitization helpers
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed.replace(/[<>\"']/g, '');
};

const isValidTokenFormat = (token: any): boolean => {
    if (typeof token !== 'string') return false;
    return /^\d{4}-\d{4}-\d{4}-\d{4}$/.test(token);
};

const generateToken = (): string => {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(Math.floor(1000 + Math.random() * 9000).toString());
    }
    return segments.join('-');
};

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// HMAC Signature Verification Middleware
const verifyApiAuth = (req: Request, res: Response, next: Function): void => {
    const API_KEY = process.env.API_KEY;
    const API_SECRET = process.env.API_SECRET;
    const apiKey = req.headers['x-api-key'] as string;
    const timestamp = req.headers['x-timestamp'] as string;
    const signature = req.headers['x-signature'] as string;

    if (!apiKey || !timestamp || !signature) {
        res.status(401).json({ error: 'Missing authentication headers' });
        return;
    }

    if (apiKey !== API_KEY) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
    }

    const now = Math.floor(Date.now() / 1000);
    const reqTime = parseInt(timestamp, 10);
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 300) {
        res.status(401).json({ error: 'Request expired or invalid timestamp' });
        return;
    }

    const bodyString = JSON.stringify(req.body || {});
    const payload = `${apiKey}:${timestamp}:${bodyString}`;
    const expectedSig = crypto
        .createHmac('sha256', API_SECRET!)
        .update(payload)
        .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
        res.status(401).json({ error: 'Invalid signature' });
        return;
    }

    next();
};

// API Register Merchant
router.post('/register-merchant', verifyApiAuth, async (req: Request, res: Response) => {
    const { 
        name, 
        merchant_name, 
        email, 
        phone, 
        province, 
        city, 
        district, 
        subdistrict, 
        postal_code, 
        street_address, 
        package: pkg, 
        amount,
        device_id,
        device_name,
        device_type 
    } = req.body;

    if (!name || !merchant_name || !email || !phone || !province || !city || !district || !subdistrict || !postal_code || !street_address || amount === undefined || amount === null || amount === '') {
        return res.status(400).json({ error: 'All fields are required: name, merchant_name, email, phone, province, city, district, subdistrict, postal_code, street_address, amount' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const parsedAmount = parseFloat(amount.toString());
    if (isNaN(parsedAmount) || parsedAmount < 0) {
        return res.status(400).json({ error: 'Invalid amount value' });
    }

    const sanitizedName = sanitizeString(name, 100);
    const sanitizedMerchantName = sanitizeString(merchant_name, 255);
    const sanitizedEmail = sanitizeString(email, 100)?.toLowerCase();
    const sanitizedPhone = sanitizeString(phone, 20);
    const sanitizedProvince = sanitizeString(province, 100);
    const sanitizedCity = sanitizeString(city, 100);
    const sanitizedDistrict = sanitizeString(district, 100);
    const sanitizedSubdistrict = sanitizeString(subdistrict, 100);
    const sanitizedPostalCode = sanitizeString(postal_code, 10);
    const sanitizedStreetAddress = sanitizeString(street_address, 500);
    const sanitizedDeviceId = sanitizeString(device_id, 255);
    const sanitizedDeviceName = sanitizeString(device_name, 255);
    const sanitizedDeviceType = sanitizeString(device_type, 255);

    if (!sanitizedName || !sanitizedMerchantName || !sanitizedEmail || !sanitizedPhone || !sanitizedProvince || !sanitizedCity || !sanitizedDistrict || !sanitizedSubdistrict || !sanitizedPostalCode || !sanitizedStreetAddress) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    // Determine package and amount
    const packageName = parsedAmount === 0 ? 'trial' : 'premium';
    const packageAmount = parsedAmount;

    if (!['trial', 'premium'].includes(packageName)) {
        return res.status(400).json({ error: 'Invalid package. Use "trial" or "premium"' });
    }

    let client;
    try {
        client = await pool.connect();

        // Check if email or phone already registered
        const checkQuery = `
            SELECT email, phone FROM merchants 
            WHERE email = $1 OR phone = $2
            LIMIT 1
        `;
        const checkResult = await client.query(checkQuery, [sanitizedEmail, sanitizedPhone]);
        
        if (checkResult.rows.length > 0) {
            const existingEmail = checkResult.rows[0].email === sanitizedEmail;
            const existingPhone = checkResult.rows[0].phone === sanitizedPhone;
            
            let errorMessage = 'Registration failed. ';
            if (existingEmail && existingPhone) {
                errorMessage += 'Email and phone already registered.';
            } else if (existingEmail) {
                errorMessage += 'Email already registered.';
            } else {
                errorMessage += 'Phone already registered.';
            }
            
            return res.status(409).json({ error: errorMessage });
        }

        // Check if device_id, device_name, and device_type combination is already registered
        if (sanitizedDeviceId && sanitizedDeviceName && sanitizedDeviceType) {
            const deviceCheckQuery = `
                SELECT token_number FROM merchants 
                WHERE device_id = $1 AND device_name = $2 AND device_type = $3
                LIMIT 1
            `;
            const deviceCheckResult = await client.query(deviceCheckQuery, [sanitizedDeviceId, sanitizedDeviceName, sanitizedDeviceType]);
            
            if (deviceCheckResult.rows.length > 0) {
                return res.status(409).json({ error: 'perangkat anda sudah terdaftar' });
            }
        }

        const token = generateToken();
        const orderId = `${packageName === 'trial' ? 'TRIAL' : 'PREMIUM'}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const activationLink = `${req.protocol}://${req.get('host')}/v1/activate-merchant?token=${token}`;

        // If trial, register with inactive status
        if (packageName === 'trial') {
            const insertQuery = `
                INSERT INTO merchants (token_number, order_id, name, merchant_name, email, phone, province, city, district, subdistrict, postal_code, street_address, package, amount, status, payment_status, pg_order_id, register_date, status_active, device_id, device_name, device_type)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'trial', 'paid', NULL, NOW(), false, $15, $16, $17)
                RETURNING *
            `;
            const result = await client.query(insertQuery, [token, orderId, sanitizedName, sanitizedMerchantName, sanitizedEmail, sanitizedPhone, sanitizedProvince, sanitizedCity, sanitizedDistrict, sanitizedSubdistrict, sanitizedPostalCode, sanitizedStreetAddress, packageName, packageAmount, sanitizedDeviceId, sanitizedDeviceName, sanitizedDeviceType]);

            // Send token email for trial with activation link
            await sendPaymentSuccessEmail(sanitizedEmail, sanitizedName, sanitizedMerchantName || sanitizedName, token, packageName, activationLink);

            return res.status(201).json({
                success: true,
                message: 'Trial registration successful',
                data: {
                    token: token,
                    order_id: orderId,
                    package: 'trial',
                    status: 'trial',
                    payment_status: 'paid',
                    activation_url: activationLink,
                    ...result.rows[0]
                }
            });
        }

        // If premium, handle payment gateway
        const activePaymentGateway = await getConfig('ACTIVE_PAYMENT_GATEWAY', 'midtrans');
        let paymentUrl = '';
        
        if (activePaymentGateway === 'midtrans') {
            const transactionDetails = {
                transaction_details: {
                    order_id: orderId,
                    gross_amount: packageAmount
                },
                customer_details: {
                    first_name: sanitizedName,
                    email: sanitizedEmail,
                    phone: sanitizedPhone
                },
                item_details: [{
                    id: packageName,
                    price: packageAmount,
                    quantity: 1,
                    name: `Ukasir ${packageName.charAt(0).toUpperCase() + packageName.slice(1)} Package`
                }]
            };

            const snap = await getMidtransSnap();
            const transaction = await snap.createTransaction(transactionDetails);
            paymentUrl = transaction.redirect_url;
        } else if (activePaymentGateway === 'duitku') {
            const merchantCode = await getConfig('DUITKU_MERCHANT_CODE');
            const apiKey = await getConfig('DUITKU_API_KEY');
            const isProduction = await getConfig('DUITKU_IS_PRODUCTION') === 'true';
            
            const apiUrl = isProduction 
                ? 'https://passport.duitku.com/webapi/api/merchant/v2/inquiry' 
                : 'https://sandbox.duitku.com/webapi/api/merchant/v2/inquiry';
                
            const signature = crypto.createHash('md5').update(`${merchantCode}${orderId}${packageAmount}${apiKey}`).digest('hex');
            
            const callbackUrl = `${req.protocol}://${req.get('host')}/v1/duitku-notification`;
            const returnUrl = 'ukasir://';
            
            const duitkuPayload = {
                merchantCode,
                paymentAmount: packageAmount,
                merchantOrderId: orderId,
                productDetails: `Ukasir ${packageName.charAt(0).toUpperCase() + packageName.slice(1)} Package`,
                email: sanitizedEmail,
                customerVaName: sanitizedName,
                phoneNumber: sanitizedPhone,
                callbackUrl,
                returnUrl,
                signature
            };
            
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(duitkuPayload)
            });
            
            const responseData = await response.json() as any;
            
            if (responseData.statusCode !== '00') {
                throw new Error(`Duitku error: ${responseData.statusMessage}`);
            }
            
            paymentUrl = responseData.paymentUrl;
        }

        // Save to database with pending status and inactive status_active
        const insertQuery = `
            INSERT INTO merchants (token_number, order_id, name, merchant_name, email, phone, province, city, district, subdistrict, postal_code, street_address, package, amount, status, payment_url, payment_status, pg_order_id, register_date, status_active, device_id, device_name, device_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pending', $15, 'pending', NULL, NOW(), false, $16, $17, $18)
            RETURNING *
        `;
        const result = await client.query(insertQuery, [token, orderId, sanitizedName, sanitizedMerchantName, sanitizedEmail, sanitizedPhone, sanitizedProvince, sanitizedCity, sanitizedDistrict, sanitizedSubdistrict, sanitizedPostalCode, sanitizedStreetAddress, packageName, packageAmount, paymentUrl, sanitizedDeviceId, sanitizedDeviceName, sanitizedDeviceType]);

        // Send payment email (payment button only, no activation link)
        await sendPaymentEmail(sanitizedEmail, sanitizedName, sanitizedMerchantName || sanitizedName, paymentUrl, packageAmount, packageName);

        return res.status(201).json({
            success: true,
            message: 'Registration successful. Please complete payment.',
            data: {
                token: token,
                order_id: orderId,
                package: packageName,
                amount: packageAmount,
                status: 'pending',
                payment_status: 'pending',
                payment_url: paymentUrl,
                activation_url: activationLink,
                instruction: 'Please complete payment within 24 hours'
            }
        });

    } catch (error: any) {
        console.error('Registration error:', error);
        
        if (error.ApiResponse?.error_messages) {
            console.error('Midtrans API Error Messages:', error.ApiResponse.error_messages);
        } else if (error.response?.data) {
            console.error('Midtrans Response Data:', JSON.stringify(error.response.data, null, 2));
        }
        
        if (error.code === '23505') {
            return res.status(409).json({
                error: 'Email or phone already registered'
            });
        }
        
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// GET Activate Merchant
router.get('/activate-merchant', async (req: Request, res: Response) => {
    const token = req.query.token as string;

    if (!token || !isValidTokenFormat(token)) {
        return res.status(400).send(renderActivationPage(false, 'Format token tidak valid. Token harus berformat XXXX-XXXX-XXXX-XXXX.'));
    }

    let client;
    try {
        client = await pool.connect();

        // Get merchant details
        const query = 'SELECT token_number, status_active, package, payment_status, exclusive_merchant FROM merchants WHERE token_number = $1';
        const result = await client.query(query, [token]);

        if (result.rows.length === 0) {
            return res.status(404).send(renderActivationPage(false, 'Token merchant tidak ditemukan.'));
        }

        const merchant = result.rows[0];

        // Check if premium package requires payment first
        if (merchant.package === 'premium' && merchant.payment_status !== 'paid') {
            return res.status(400).send(renderActivationPage(false, 'Silakan selesaikan pembayaran Anda terlebih dahulu sebelum mengaktifkan akun.'));
        }

        // If already active
        if (merchant.status_active) {
            return res.send(renderActivationPage(true, 'Akun Anda sudah aktif sebelumnya. Silakan gunakan token untuk login di aplikasi Ukasir.', merchant.exclusive_merchant));
        }

        // Activate merchant
        const updateQuery = 'UPDATE merchants SET status_active = true, updated_at = NOW() WHERE token_number = $1';
        await client.query(updateQuery, [token]);

        return res.send(renderActivationPage(true, 'Akun Ukasir Anda berhasil diaktifkan! Silakan gunakan token Anda untuk login di aplikasi.', merchant.exclusive_merchant));

    } catch (error: any) {
        console.error('Activation error:', error);
        return res.status(500).send(renderActivationPage(false, 'Terjadi kesalahan pada server saat memproses aktivasi.'));
    } finally {
        if (client) client.release();
    }
});

// Get All Merchants List (Protected)
router.get('/merchants', verifyApiAuth, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        // Get query parameters for pagination and filtering
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const status = req.query.status as string;
        const search = req.query.search as string;

        const offset = (page - 1) * limit;

        // Build query conditions
        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (status) {
            whereConditions.push(`status = $${paramIndex}`);
            queryParams.push(status);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`(name ILIKE $${paramIndex} OR email ILIKE $${paramIndex} OR phone ILIKE $${paramIndex} OR merchant_name ILIKE $${paramIndex})`);
            queryParams.push(`%${search}%`);
            paramIndex++;
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

        // Get total count
        const countQuery = `SELECT COUNT(*) FROM merchants ${whereClause}`;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        // Get merchants data
        const dataQuery = `
            SELECT 
                token_number,
                order_id,
                name,
                merchant_name,
                email,
                phone,
                province,
                city,
                district,
                subdistrict,
                postal_code,
                street_address,
                package,
                amount,
                status,
                payment_method,
                payment_status,
                pg_order_id,
                paid_at,
                register_date,
                status_active,
                device_id,
                device_name,
                device_type,
                referral_code,
                exclusive_merchant,
                created_at,
                updated_at
            FROM merchants 
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.status(200).json({
            success: true,
            message: 'Merchants retrieved successfully',
            data: dataResult.rows,
            pagination: {
                current_page: page,
                per_page: limit,
                total_items: total,
                total_pages: totalPages,
                has_next: page < totalPages,
                has_prev: page > 1
            }
        });

    } catch (error: any) {
        console.error('Get merchants error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Get Merchant by Token Number (Protected)
router.get('/merchants/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    let client;
    try {
        client = await pool.connect();

        const query = `
            SELECT * FROM merchants 
            WHERE token_number = $1
            LIMIT 1
        `;
        const result = await client.query(query, [token]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Merchant not found'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Merchant retrieved successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Get merchant error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Update Merchant (Protected)
router.put('/merchants/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    const { name, merchant_name, email, phone, province, city, district, subdistrict, postal_code, street_address, package: pkg, status, status_active, register_date, exclusive_merchant } = req.body;
    let client;
    try {
        client = await pool.connect();

        // Check if merchant exists
        const checkQuery = 'SELECT * FROM merchants WHERE token_number = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [token]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        const existingMerchant = checkResult.rows[0];

        // Validate email format if email is being updated
        if (email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
        }

        // Sanitize inputs
        const sanitizedName = sanitizeString(name, 100) || existingMerchant.name;
        const sanitizedMerchantName = sanitizeString(merchant_name, 255) || existingMerchant.merchant_name;
        const sanitizedEmail = (email ? sanitizeString(email, 100)?.toLowerCase() : existingMerchant.email);
        const sanitizedPhone = sanitizeString(phone, 20) || existingMerchant.phone;
        const sanitizedProvince = province !== undefined ? (sanitizeString(province, 100) || null) : existingMerchant.province;
        const sanitizedCity = city !== undefined ? (sanitizeString(city, 100) || null) : existingMerchant.city;
        const sanitizedDistrict = district !== undefined ? (sanitizeString(district, 100) || null) : existingMerchant.district;
        const sanitizedSubdistrict = subdistrict !== undefined ? (sanitizeString(subdistrict, 100) || null) : existingMerchant.subdistrict;
        const sanitizedPostalCode = postal_code !== undefined ? (sanitizeString(postal_code, 10) || null) : existingMerchant.postal_code;
        const sanitizedStreetAddress = street_address !== undefined ? (sanitizeString(street_address, 500) || null) : existingMerchant.street_address;
        const sanitizedPackage = pkg || existingMerchant.package;
        const sanitizedStatus = status || existingMerchant.status;
        const sanitizedStatusActive = status_active !== undefined ? Boolean(status_active) : existingMerchant.status_active;
        const sanitizedRegisterDate = register_date !== undefined ? new Date(register_date) : existingMerchant.register_date;

        const sanitizedExclusiveMerchant = exclusive_merchant !== undefined
            ? (exclusive_merchant === null || exclusive_merchant === '' ? null : parseInt(exclusive_merchant.toString(), 10))
            : existingMerchant.exclusive_merchant;

        if (sanitizedExclusiveMerchant !== null && (isNaN(sanitizedExclusiveMerchant) || sanitizedExclusiveMerchant < 1)) {
            return res.status(400).json({ error: 'Invalid exclusive_merchant. Must be a positive integer or null.' });
        }

        if (!sanitizedName || !sanitizedEmail || !sanitizedPhone) {
            return res.status(400).json({ error: 'Invalid input data' });
        }

        // Check for duplicate email/phone (excluding current merchant)
        const duplicateQuery = `
            SELECT email, phone FROM merchants 
            WHERE (email = $1 OR phone = $2) AND token_number != $3
            LIMIT 1
        `;
        const duplicateResult = await client.query(duplicateQuery, [sanitizedEmail, sanitizedPhone, token]);

        if (duplicateResult.rows.length > 0) {
            const existingEmail = duplicateResult.rows[0].email === sanitizedEmail;
            const existingPhone = duplicateResult.rows[0].phone === sanitizedPhone;
            
            let errorMessage = 'Update failed. ';
            if (existingEmail && existingPhone) {
                errorMessage += 'Email and phone already registered by another merchant.';
            } else if (existingEmail) {
                errorMessage += 'Email already registered by another merchant.';
            } else {
                errorMessage += 'Phone already registered by another merchant.';
            }
            
            return res.status(409).json({ error: errorMessage });
        }

        // Update merchant
        const updateQuery = `
            UPDATE merchants SET
                name = $1,
                merchant_name = $2,
                email = $3,
                phone = $4,
                province = $5,
                city = $6,
                district = $7,
                subdistrict = $8,
                postal_code = $9,
                street_address = $10,
                package = $11,
                status = $12,
                status_active = $13,
                register_date = $14,
                exclusive_merchant = $15,
                updated_at = NOW()
            WHERE token_number = $16
            RETURNING *
        `;

        const result = await client.query(updateQuery, [
            sanitizedName,
            sanitizedMerchantName,
            sanitizedEmail,
            sanitizedPhone,
            sanitizedProvince,
            sanitizedCity,
            sanitizedDistrict,
            sanitizedSubdistrict,
            sanitizedPostalCode,
            sanitizedStreetAddress,
            sanitizedPackage,
            sanitizedStatus,
            sanitizedStatusActive,
            sanitizedRegisterDate,
            sanitizedExclusiveMerchant,
            token
        ]);

        return res.status(200).json({
            success: true,
            message: 'Merchant updated successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update merchant error:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                error: 'Email or phone already registered by another merchant'
            });
        }
        
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Delete Merchant (Protected)
router.delete('/merchants/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    let client;
    try {
        client = await pool.connect();

        // Check if merchant exists
        const checkQuery = 'SELECT * FROM merchants WHERE token_number = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [token]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        const merchant = checkResult.rows[0];

        // Delete merchant
        const deleteQuery = 'DELETE FROM merchants WHERE token_number = $1 RETURNING *';
        const result = await client.query(deleteQuery, [token]);

        return res.status(200).json({
            success: true,
            message: 'Merchant deleted successfully',
            data: {
                token_number: result.rows[0].token_number,
                name: result.rows[0].name,
                email: result.rows[0].email,
                deleted_at: new Date().toISOString()
            }
        });

    } catch (error: any) {
        console.error('Delete merchant error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Midtrans Webhook Handler
router.post('/payment-notification', async (req: Request, res: Response) => {
    const notification = req.body;
    const orderId = notification.order_id;
    const transactionStatus = notification.transaction_status;
    const paymentType = notification.payment_type;
    const grossAmount = notification.gross_amount;
    const transactionTime = notification.transaction_time;

    // Verify Midtrans signature
    const midtransSignature = req.headers['x-midtrans-signature'] as string;
    
    if (midtransSignature) {
        const serverKey = await getConfig('MIDTRANS_SERVER_KEY');
        const expectedSignature = crypto
            .createHash('sha512')
            .update(`${notification.order_id}${notification.status_code}${notification.gross_amount}${serverKey}`)
            .digest('hex');

        if (midtransSignature !== expectedSignature) {
            console.error('Invalid Midtrans signature');
            return res.status(403).json({ error: 'Invalid signature' });
        }
    }

    console.log('Payment notification received:', notification);

    let client;
    try {
        client = await pool.connect();

        // Start transaction
        await client.query('BEGIN');

        // Check if cashier transaction
        if (orderId && orderId.startsWith('TRX-')) {
            let newPaymentStatus = 'pending';
            if (transactionStatus === 'settlement' || transactionStatus === 'capture') {
                newPaymentStatus = 'paid';
            } else if (transactionStatus === 'expire') {
                newPaymentStatus = 'expired';
            } else if (transactionStatus === 'cancel' || transactionStatus === 'deny') {
                newPaymentStatus = 'failed';
            }

            const updateQuery = `
                UPDATE cashier_transactions 
                SET payment_status = $1, updated_at = NOW()
                WHERE order_id = $2
                RETURNING *
            `;
            await client.query(updateQuery, [newPaymentStatus, orderId]);
            await client.query('COMMIT');
            
            console.log(`Cashier transaction updated: ${orderId} - ${newPaymentStatus}`);
            return res.json({
                status: 'ok',
                message: 'Cashier payment notification received'
            });
        }

        // Find merchant by order_id or pg_order_id and lock the row
        const findQuery = 'SELECT * FROM merchants WHERE order_id = $1 OR pg_order_id = $1 FOR UPDATE';
        const findResult = await client.query(findQuery, [orderId]);

        if (findResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Order not found' });
        }

        const merchant = findResult.rows[0];

        // Update payment status based on transaction status
        let newStatus = merchant.status;
        let newPaymentStatus = transactionStatus;
        let statusActive = merchant.status_active;
        let paidAt = merchant.paid_at;
        let exclusiveMerchant = merchant.exclusive_merchant;

        if (transactionStatus === 'settlement' || transactionStatus === 'capture') {
            // Payment successful
            newPaymentStatus = 'paid';
            newStatus = 'premium';
            statusActive = true;
            paidAt = new Date();

            // Assign exclusive_merchant number if not already assigned and is a premium package
            if (merchant.package === 'premium' && !exclusiveMerchant) {
                // Lock the merchants table to serialize exclusive_merchant calculations across concurrent requests
                await client.query('LOCK TABLE merchants IN SHARE ROW EXCLUSIVE MODE');

                const maxQuery = 'SELECT COALESCE(MAX(exclusive_merchant), 0) as max_val FROM merchants';
                const maxResult = await client.query(maxQuery);
                const maxVal = parseInt(maxResult.rows[0].max_val, 10);

                if (maxVal < 100) {
                    exclusiveMerchant = maxVal + 1;
                }
            }
        } else if (transactionStatus === 'pending') {
            // Waiting for payment
            newPaymentStatus = 'pending';
        } else if (transactionStatus === 'expire' || transactionStatus === 'cancel') {
            // Payment expired or cancelled
            newPaymentStatus = transactionStatus;
            newStatus = 'failed';
        }

        // Update database
        const updateQuery = `
            UPDATE merchants 
            SET status = $1, payment_status = $2, status_active = $3, paid_at = $4, payment_method = $5, exclusive_merchant = $6, updated_at = NOW()
            WHERE order_id = $7 OR pg_order_id = $7
            RETURNING *
        `;
        const result = await client.query(updateQuery, [newStatus, newPaymentStatus, statusActive, paidAt, paymentType, exclusiveMerchant, orderId]);

        // Commit transaction
        await client.query('COMMIT');

        console.log(`Payment updated: ${orderId} - ${transactionStatus}, Exclusive Merchant #: ${exclusiveMerchant || 'None'}`);

        // Send success email with token if payment is successful
        if (transactionStatus === 'settlement' || transactionStatus === 'capture') {
            const updatedMerchant = result.rows[0];
            const activationLink = `${req.protocol}://${req.get('host')}/v1/activate-merchant?token=${updatedMerchant.token_number}`;
            await sendPaymentSuccessEmail(
                updatedMerchant.email,
                updatedMerchant.name,
                updatedMerchant.merchant_name,
                updatedMerchant.token_number,
                updatedMerchant.package,
                activationLink
            );
        }

        return res.json({
            status: 'ok',
            message: 'Payment notification received'
        });

    } catch (error: any) {
        console.error('Webhook error:', error);
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                console.error('Rollback error:', rollbackError);
            }
        }
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Duitku Webhook Handler
router.post('/duitku-notification', async (req: Request, res: Response) => {
    const { merchantCode, amount, merchantOrderId, signature, reference, resultCode } = req.body;

    const apiKey = await getConfig('DUITKU_API_KEY');
    
    if (!merchantCode || !amount || !merchantOrderId || !signature) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    const expectedSignature = crypto
        .createHash('md5')
        .update(`${merchantCode}${amount}${merchantOrderId}${apiKey}`)
        .digest('hex');

    if (signature !== expectedSignature) {
        console.error('Invalid Duitku signature');
        return res.status(403).json({ error: 'Invalid signature' });
    }

    console.log('Duitku payment notification received:', req.body);

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // Find merchant by order_id and lock the row
        const findQuery = 'SELECT * FROM merchants WHERE order_id = $1 FOR UPDATE';
        const findResult = await client.query(findQuery, [merchantOrderId]);

        if (findResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Order not found' });
        }

        const merchant = findResult.rows[0];

        let newStatus = merchant.status;
        let newPaymentStatus = 'pending';
        let statusActive = merchant.status_active;
        let paidAt = merchant.paid_at;
        let exclusiveMerchant = merchant.exclusive_merchant;

        if (resultCode === '00') {
            // Payment successful
            newPaymentStatus = 'paid';
            newStatus = 'premium';
            statusActive = true;
            paidAt = new Date();

            if (merchant.package === 'premium' && !exclusiveMerchant) {
                await client.query('LOCK TABLE merchants IN SHARE ROW EXCLUSIVE MODE');
                const maxQuery = 'SELECT COALESCE(MAX(exclusive_merchant), 0) as max_val FROM merchants';
                const maxResult = await client.query(maxQuery);
                const maxVal = parseInt(maxResult.rows[0].max_val, 10);
                if (maxVal < 100) {
                    exclusiveMerchant = maxVal + 1;
                }
            }
        } else if (resultCode === '01') {
            newPaymentStatus = 'failed';
            newStatus = 'failed';
        }

        // Update database
        const updateQuery = `
            UPDATE merchants 
            SET status = $1, payment_status = $2, status_active = $3, paid_at = $4, exclusive_merchant = $5, updated_at = NOW()
            WHERE order_id = $6
            RETURNING *
        `;
        const result = await client.query(updateQuery, [newStatus, newPaymentStatus, statusActive, paidAt, exclusiveMerchant, merchantOrderId]);
        await client.query('COMMIT');

        console.log(`Duitku Payment updated: ${merchantOrderId} - Code: ${resultCode}`);

        // Send email if successful
        if (resultCode === '00') {
            const updatedMerchant = result.rows[0];
            const activationLink = `${req.protocol}://${req.get('host')}/v1/activate-merchant?token=${updatedMerchant.token_number}`;
            await sendPaymentSuccessEmail(
                updatedMerchant.email,
                updatedMerchant.name,
                updatedMerchant.merchant_name,
                updatedMerchant.token_number,
                updatedMerchant.package,
                activationLink
            );
        }

        return res.json({ status: 'ok' });
    } catch (error: any) {
        console.error('Duitku webhook error:', error);
        if (client) {
            try { await client.query('ROLLBACK'); } catch (e) {}
        }
        return res.status(500).json({ error: 'Internal Server Error' });
    } finally {
        if (client) client.release();
    }
});

// Check Payment Status
router.get('/payment-status/:order_id', async (req: Request, res: Response) => {
    const { order_id } = req.params;

    let client;
    try {
        client = await pool.connect();

        const query = 'SELECT token_number, order_id, package, amount, status, payment_status, payment_url, paid_at FROM merchants WHERE order_id = $1 OR pg_order_id = $1';
        const result = await client.query(query, [order_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        return res.json({
            success: true,
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Payment status error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Background job to send payment reminders every 5 minutes
const REMINDER_INTERVAL = 5 * 60 * 1000; // 5 minutes

setInterval(async () => {
    let client;
    try {
        client = await pool.connect();
        
        // Find premium merchants with pending payment status registered in the last 24 hours
        const query = `
            SELECT token_number, name, merchant_name, email, payment_url, amount, package 
            FROM merchants 
            WHERE package = 'premium' 
              AND payment_status = 'pending' 
              AND created_at >= NOW() - INTERVAL '24 hours'
        `;
        const result = await client.query(query);
        
        if (result.rows.length > 0) {
            console.log(`[Payment Reminder] Found ${result.rows.length} pending premium merchants. Sending emails...`);
            for (const merchant of result.rows) {
                try {
                    const parsedAmount = parseFloat(merchant.amount);
                    await sendPaymentEmail(
                        merchant.email,
                        merchant.name,
                        merchant.merchant_name || merchant.name,
                        merchant.payment_url,
                        parsedAmount,
                        merchant.package
                    );
                    console.log(`[Payment Reminder] Sent reminder email to ${merchant.email}`);
                } catch (emailError) {
                    console.error(`[Payment Reminder] Failed to send email to ${merchant.email}:`, emailError);
                }
            }
        }
    } catch (error) {
        console.error('[Payment Reminder] Cron job execution error:', error);
    } finally {
        if (client) client.release();
    }
}, REMINDER_INTERVAL);

export default router;
