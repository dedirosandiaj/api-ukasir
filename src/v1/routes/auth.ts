import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';

// @ts-ignore - midtrans-client doesn't have types
import midtransClient from 'midtrans-client';

dotenv.config();

// Initialize Midtrans Snap API
const isProduction = process.env.MIDTRANS_IS_PRODUCTION === 'true';
const snap = new midtransClient.Snap({
    isProduction: isProduction,
    serverKey: process.env.MIDTRANS_SERVER_KEY,
    clientKey: process.env.MIDTRANS_CLIENT_KEY
});

// Initialize Nodemailer
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465'),
    secure: true, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
    }
});

const router = Router();

// Helper function to send payment email
const sendPaymentEmail = async (email: string, name: string, merchantName: string, paymentUrl: string, amount: number, packageName: string) => {
    try {
        const mailOptions = {
            from: process.env.SMTP_FROM,
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
                    
                    <p style="color: #6b7280; font-size: 14px;">This payment link will expire in 24 hours.</p>
                    <p style="color: #6b7280; font-size: 14px;">If you have any questions, please contact our support team.</p>
                    
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;"/>
                    <p style="color: #9ca3af; font-size: 12px; text-align: center;">© 2026 Ukasir. All rights reserved.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('Payment email sent to:', email);
    } catch (error) {
        console.error('Failed to send payment email:', error);
    }
};

// Helper function to send payment success email with token
const sendPaymentSuccessEmail = async (email: string, name: string, merchantName: string, token: string, packageName: string) => {
    try {
        const mailOptions = {
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'Payment Successful - Your Ukasir Token',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #10b981;">🎉 Payment Successful!</h2>
                    <p>Thank you for your payment. Your Ukasir account is now active!</p>
                    
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Account Details:</h3>
                        <p style="margin: 5px 0;"><strong>Name:</strong> ${name}</p>
                        <p style="margin: 5px 0;"><strong>Merchant:</strong> ${merchantName}</p>
                    </div>
                    
                    <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
                        <h3 style="margin: 0 0 10px 0;">Your Activation Token:</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #2563eb; letter-spacing: 2px; margin: 10px 0;">${token}</p>
                        <p style="margin: 5px 0; color: #6b7280; font-size: 14px;">Package: ${packageName.charAt(0).toUpperCase() + packageName.slice(1)}</p>
                    </div>
                    
                    <div style="background: #dbeafe; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin: 0 0 10px 0;">Next Steps:</h3>
                        <ol style="margin: 10px 0; padding-left: 20px;">
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

        await transporter.sendMail(mailOptions);
        console.log('Payment success email sent to:', email);
    } catch (error) {
        console.error('Failed to send payment success email:', error);
    }
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
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
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
    const { name, merchant_name, email, phone, address, city, subdistrict, regency, province, postal_code, package: pkg, amount } = req.body;

    if (!name || !merchant_name || !email || !phone || !address || !city || !subdistrict || !regency || !province || !postal_code) {
        return res.status(400).json({ error: 'All fields are required: name, merchant_name, email, phone, address, city, subdistrict, regency, province, postal_code' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const sanitizedName = sanitizeString(name, 100);
    const sanitizedMerchantName = sanitizeString(merchant_name, 255);
    const sanitizedEmail = sanitizeString(email, 100)?.toLowerCase();
    const sanitizedPhone = sanitizeString(phone, 20);
    const sanitizedAddress = sanitizeString(address, 500);
    const sanitizedCity = sanitizeString(city, 100);
    const sanitizedSubdistrict = sanitizeString(subdistrict, 100);
    const sanitizedRegency = sanitizeString(regency, 100);
    const sanitizedProvince = sanitizeString(province, 100);
    const sanitizedPostalCode = sanitizeString(postal_code, 10);

    if (!sanitizedName || !sanitizedMerchantName || !sanitizedEmail || !sanitizedPhone || !sanitizedAddress || !sanitizedCity || !sanitizedSubdistrict || !sanitizedRegency || !sanitizedProvince || !sanitizedPostalCode) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    // Determine package and amount
    const packageName = pkg || (amount > 0 ? 'premium' : 'trial');
    const packageAmount = amount || (packageName === 'trial' ? 0 : 145000);

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

        const token = generateToken();
        const orderId = `${packageName === 'trial' ? 'TRIAL' : 'PREMIUM'}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        // If trial, activate immediately
        if (packageName === 'trial') {
            const insertQuery = `
                INSERT INTO merchants (token_number, order_id, name, merchant_name, email, phone, address, city, subdistrict, regency, province, postal_code, package, amount, status, payment_status, midtrans_order_id, register_date, status_active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'trial', 'paid', NULL, NOW(), true)
                RETURNING *
            `;
            const result = await client.query(insertQuery, [token, orderId, sanitizedName, sanitizedMerchantName, sanitizedEmail, sanitizedPhone, sanitizedAddress, sanitizedCity, sanitizedSubdistrict, sanitizedRegency, sanitizedProvince, sanitizedPostalCode, packageName, packageAmount]);

            // Send token email for trial
            await sendPaymentSuccessEmail(sanitizedEmail, sanitizedName, sanitizedMerchantName || sanitizedName, token, packageName);

            return res.status(201).json({
                success: true,
                message: 'Trial registration successful',
                data: {
                    token: token,
                    order_id: orderId,
                    package: 'trial',
                    status: 'trial',
                    payment_status: 'paid',
                    ...result.rows[0]
                }
            });
        }

        // If premium, create Midtrans transaction
        const midtransOrderId = `ORDER-${Date.now()}`;
        const transactionDetails = {
            transaction_details: {
                order_id: midtransOrderId,
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

        const transaction = await snap.createTransaction(transactionDetails);
        const paymentUrl = transaction.redirect_url;

        // Save to database with pending status
        const insertQuery = `
            INSERT INTO merchants (token_number, order_id, name, merchant_name, email, phone, address, city, subdistrict, regency, province, postal_code, package, amount, status, payment_url, payment_status, midtrans_order_id, register_date, status_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pending', $15, 'pending', $16, NOW(), false)
            RETURNING *
        `;
        const result = await client.query(insertQuery, [token, orderId, sanitizedName, sanitizedMerchantName, sanitizedEmail, sanitizedPhone, sanitizedAddress, sanitizedCity, sanitizedSubdistrict, sanitizedRegency, sanitizedProvince, sanitizedPostalCode, packageName, packageAmount, paymentUrl, midtransOrderId]);

        // Send payment email
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
                midtrans_order_id: midtransOrderId,
                instruction: 'Please complete payment within 24 hours'
            }
        });

    } catch (error: any) {
        console.error('Registration error:', error);
        
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
        const expectedSignature = crypto
            .createHash('sha512')
            .update(`${notification.order_id}${notification.status_code}${notification.gross_amount}${process.env.MIDTRANS_SERVER_KEY}`)
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

        // Find merchant by midtrans_order_id
        const findQuery = 'SELECT * FROM merchants WHERE midtrans_order_id = $1';
        const findResult = await client.query(findQuery, [orderId]);

        if (findResult.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const merchant = findResult.rows[0];

        // Update payment status based on transaction status
        let newStatus = merchant.status;
        let newPaymentStatus = transactionStatus;
        let statusActive = merchant.status_active;
        let paidAt = merchant.paid_at;

        if (transactionStatus === 'settlement' || transactionStatus === 'capture') {
            // Payment successful
            newPaymentStatus = 'paid';
            newStatus = 'premium';
            statusActive = true;
            paidAt = new Date();
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
            SET status = $1, payment_status = $2, status_active = $3, paid_at = $4, payment_method = $5, updated_at = NOW()
            WHERE midtrans_order_id = $6
            RETURNING *
        `;
        const result = await client.query(updateQuery, [newStatus, newPaymentStatus, statusActive, paidAt, paymentType, orderId]);

        console.log(`Payment updated: ${orderId} - ${transactionStatus}`);

        // Send success email with token if payment is successful
        if (transactionStatus === 'settlement' || transactionStatus === 'capture') {
            const updatedMerchant = result.rows[0];
            await sendPaymentSuccessEmail(
                updatedMerchant.email,
                updatedMerchant.name,
                updatedMerchant.merchant_name,
                updatedMerchant.token_number,
                updatedMerchant.package
            );
        }

        return res.json({
            status: 'ok',
            message: 'Payment notification received'
        });

    } catch (error: any) {
        console.error('Webhook error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
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

        const query = 'SELECT token_number, order_id, package, amount, status, payment_status, payment_url, paid_at FROM merchants WHERE order_id = $1 OR midtrans_order_id = $1';
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

export default router;
