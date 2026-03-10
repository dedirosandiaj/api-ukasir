import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import { Resend } from 'resend';

dotenv.config();

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// API Authentication Config
const API_KEY = process.env.API_KEY;
const API_SECRET = process.env.API_SECRET;

if (!API_KEY || !API_SECRET) {
    console.error('ERROR: API_KEY and API_SECRET must be set in environment variables');
    process.exit(1);
}

// HMAC Signature Verification Middleware
const verifyApiAuth = (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = req.headers['x-api-key'] as string;
    const timestamp = req.headers['x-timestamp'] as string;
    const signature = req.headers['x-signature'] as string;

    if (!apiKey || !timestamp || !signature) {
        res.status(401).json({ error: 'Missing authentication headers' });
        return;
    }

    // Verify API Key
    if (apiKey !== API_KEY) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
    }

    // Check timestamp (prevent replay attacks - 5 min window)
    const now = Math.floor(Date.now() / 1000);
    const reqTime = parseInt(timestamp, 10);
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 300) {
        res.status(401).json({ error: 'Request expired or invalid timestamp' });
        return;
    }

    // Verify HMAC Signature
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

const app = express();
app.set('trust proxy', 1);
const port = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit body size

// Rate limiting - 100 requests per 15 minutes per IP
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Stricter rate limit for token validation (10 per minute)
const validateTokenLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Too many validation attempts, please try again later.' }
});

const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    connectionTimeoutMillis: 5000 // Fail fast after 5 seconds
});

// Removed top-level pool.connect() to prevent hanging

app.get('/', (req: Request, res: Response) => {
    res.json({
        message: 'Ukasir Offline API is running (Express)',
        version: '1.0.0'
    });
});

// Input sanitization helpers
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    // Remove control characters and potential XSS
    return trimmed.replace(/[<>\"']/g, '');
};

const isValidTokenFormat = (token: any): boolean => {
    if (typeof token !== 'string') return false;
    return /^\d{4}-\d{4}-\d{4}-\d{4}$/.test(token);
};

const isValidDeviceId = (deviceId: any): boolean => {
    if (typeof deviceId !== 'string') return false;
    // Allow alphanumeric, hyphens, underscores - max 100 chars
    return /^[a-zA-Z0-9_-]{1,100}$/.test(deviceId);
};

app.post('/api/validate-token', verifyApiAuth, validateTokenLimiter, async (req: Request, res: Response) => {
    const token = req.body.token;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    // Token format validation
    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
    } 

    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT token_number, register_date, status_active FROM ukasir_token WHERE token_number = $1';
        const result = await client.query(query, [token]);

        if (result.rows.length > 0) {
            return res.json({
                valid: true,
                data: result.rows[0]
            });
        } else {
            return res.status(404).json({
                valid: false,
                message: 'Token not found or inactive'
            });
        }
    } catch (error: any) {
        console.error('Database error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

app.post('/api/update-device', verifyApiAuth, async (req: Request, res: Response) => {
    const { token, device_id, device_name, device_type } = req.body;

    if (!token || !device_id) {
        return res.status(400).json({ error: 'Token and Device ID are required' });
    }

    // Validate token format
    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format' });
    }

    // Validate device_id format
    if (!isValidDeviceId(device_id)) {
        return res.status(400).json({ error: 'Invalid device ID format' });
    }

    // Sanitize optional fields
    const sanitizedDeviceName = sanitizeString(device_name, 100);
    const sanitizedDeviceType = sanitizeString(device_type, 50);

    let client;
    try {
        client = await pool.connect();

        // 1. Check if token exists
        const checkQuery = 'SELECT token_number, device_id FROM ukasir_token WHERE token_number = $1';
        const checkResult = await client.query(checkQuery, [token]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Token not found' });
        }

        const currentDevice = checkResult.rows[0].device_id;

        // 2. Logic:
        //    - If currentDevice is NULL: First login, update it.
        //    - If currentDevice matches request device_id: All good, return success.
        //    - If currentDevice does NOT match: Multi-device login attempt, block it.

        if (!currentDevice) {
            // Case 1: First login (or no device registered yet)
            const updateQuery = `
                UPDATE ukasir_token 
                SET device_id = $1, device_name = $2, device_type = $3
                WHERE token_number = $4
            `;
            await client.query(updateQuery, [device_id, sanitizedDeviceName, sanitizedDeviceType, token]);

            return res.json({
                success: true,
                message: 'Device registered successfully'
            });

        } else if (currentDevice === device_id) {
            // Case 2: Same device
            return res.json({
                success: true,
                message: 'Device verified'
            });

        } else {
            // Case 3: Different device
            return res.status(403).json({
                success: false,
                error: 'Multi-device login not allowed. This token is already registered to another device.'
            });
        }

    } catch (error: any) {
        console.error('Database error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Generate unique token
const generateToken = (): string => {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(Math.floor(1000 + Math.random() * 9000).toString());
    }
    return segments.join('-');
};

// API Registrasi Trial User
app.post('/api/register-trial', verifyApiAuth, async (req: Request, res: Response) => {
    const { name, email, phone, device_id, device_name, device_type } = req.body;

    // Validasi input
    if (!name || !email || !phone) {
        return res.status(400).json({ error: 'Name, email, and phone are required' });
    }

    // Validasi email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Sanitasi input
    const sanitizedName = sanitizeString(name, 100);
    const sanitizedEmail = sanitizeString(email, 100)?.toLowerCase();
    const sanitizedPhone = sanitizeString(phone, 20);
    const sanitizedDeviceId = sanitizeString(device_id, 100);
    const sanitizedDeviceName = sanitizeString(device_name, 100);
    const sanitizedDeviceType = sanitizeString(device_type, 50);

    if (!sanitizedName || !sanitizedEmail || !sanitizedPhone) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    let client;
    try {
        client = await pool.connect();

        // Cek apakah device sudah pernah daftar (jika ketiga device field diisi)
        if (sanitizedDeviceId && sanitizedDeviceName && sanitizedDeviceType) {
            const checkDeviceQuery = `
                SELECT token_number FROM ukasir_token 
                WHERE device_id = $1 AND device_name = $2 AND device_type = $3
                LIMIT 1
            `;
            const deviceResult = await client.query(checkDeviceQuery, [
                sanitizedDeviceId, 
                sanitizedDeviceName, 
                sanitizedDeviceType
            ]);

            if (deviceResult.rows.length > 0) {
                return res.status(409).json({
                    error: 'Device already registered',
                    message: 'This device has already been used for trial registration'
                });
            }
        }

        // Generate token dan order_id
        const token = generateToken();
        const orderId = `TRIAL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        // Insert ke payments table
        const paymentQuery = `
            INSERT INTO payments (order_id, name, email, phone, amount, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
            RETURNING id
        `;
        await client.query(paymentQuery, [orderId, sanitizedName, sanitizedEmail, sanitizedPhone, 0, 'trial']);

        // Insert ke ukasir_token table (dengan device info jika ada)
        const tokenQuery = `
            INSERT INTO ukasir_token (token_number, register_date, status_active, order_id, name, email, phone, device_id, device_name, device_type)
            VALUES ($1, NOW(), true, $2, $3, $4, $5, $6, $7, $8)
            RETURNING token_number
        `;
        await client.query(tokenQuery, [
            token, 
            orderId, 
            sanitizedName, 
            sanitizedEmail, 
            sanitizedPhone,
            sanitizedDeviceId,
            sanitizedDeviceName,
            sanitizedDeviceType
        ]);

        // Send token via email using Resend
        try {
            console.log('Attempting to send email to:', sanitizedEmail);
            console.log('RESEND_API_KEY exists:', !!process.env.RESEND_API_KEY);
            
            const emailResult = await resend.emails.send({
                from: 'Ukasir <onboarding@resend.dev>',
                to: sanitizedEmail,
                subject: 'Your Ukasir Trial Token',
                html: `
                    <h2>Welcome to Ukasir Trial!</h2>
                    <p>Hi ${sanitizedName},</p>
                    <p>Thank you for registering. Your trial token is:</p>
                    <h3 style="background: #f0f0f0; padding: 10px; border-radius: 5px; font-family: monospace;">${token}</h3>
                    <p>Use this token to activate your Ukasir application.</p>
                    <p>Order ID: ${orderId}</p>
                    <br>
                    <p>Best regards,<br>Ukasir Team</p>
                `
            });
            
            console.log('Email sent successfully:', emailResult);
        } catch (emailError: any) {
            console.error('Failed to send email:', emailError);
            console.error('Error details:', emailError.message);
            // Continue even if email fails - token already saved to DB
        }

        return res.status(201).json({
            success: true,
            message: 'Trial registration successful. Token sent to email.',
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
        
        // Handle duplicate email/phone
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

// Vercel requires exporting the app
export default app;

// Local development and non-Vercel deployments (like Coolify)
if (!process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}
