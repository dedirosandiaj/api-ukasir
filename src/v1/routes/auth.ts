import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';

const router = Router();

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
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
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

// API Registrasi Trial User
router.post('/register-trial', verifyApiAuth, async (req: Request, res: Response) => {
    const { name, email, phone } = req.body;

    if (!name || !email || !phone) {
        return res.status(400).json({ error: 'Name, email, and phone are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const sanitizedName = sanitizeString(name, 100);
    const sanitizedEmail = sanitizeString(email, 100)?.toLowerCase();
    const sanitizedPhone = sanitizeString(phone, 20);

    if (!sanitizedName || !sanitizedEmail || !sanitizedPhone) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    let client;
    try {
        client = await pool.connect();

        const token = generateToken();
        const orderId = `TRIAL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        const paymentQuery = `
            INSERT INTO payments (order_id, name, email, phone, amount, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
            RETURNING id
        `;
        await client.query(paymentQuery, [orderId, sanitizedName, sanitizedEmail, sanitizedPhone, 0, 'trial']);

        const tokenQuery = `
            INSERT INTO ukasir_token (token_number, register_date, status_active, order_id, name, email, phone)
            VALUES ($1, NOW(), true, $2, $3, $4, $5)
            RETURNING token_number
        `;
        await client.query(tokenQuery, [token, orderId, sanitizedName, sanitizedEmail, sanitizedPhone]);

        return res.status(201).json({
            success: true,
            message: 'Trial registration successful',
            data: {
                token: token,
                order_id: orderId,
                name: sanitizedName,
                email: sanitizedEmail,
                phone: sanitizedPhone
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

export default router;
