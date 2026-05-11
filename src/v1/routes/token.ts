import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const router = Router();

// Rate limiting - 10 per minute for token validation
const validateTokenLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Too many validation attempts, please try again later.' }
});

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

const isValidDeviceId = (deviceId: any): boolean => {
    if (typeof deviceId !== 'string') return false;
    return /^[a-zA-Z0-9_-]{1,100}$/.test(deviceId);
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
const verifyApiAuth = (req: Request, res: Response, next: NextFunction): void => {
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

// Validate Token
router.post('/validate-token', verifyApiAuth, validateTokenLimiter, async (req: Request, res: Response) => {
    const token = req.body.token;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
    }

    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT token_number, register_date, status_active, package FROM merchants WHERE token_number = $1';
        const result = await client.query(query, [token]);

        if (result.rows.length > 0) {
            const merchant = result.rows[0];
            
            // Check if trial has expired (7 days)
            if (merchant.package === 'trial' && merchant.status_active) {
                const registerDate = new Date(merchant.register_date);
                const now = new Date();
                const daysSinceRegister = (now.getTime() - registerDate.getTime()) / (1000 * 60 * 60 * 24);
                
                if (daysSinceRegister > 7) {
                    // Trial expired - deactivate token
                    const updateQuery = 'UPDATE merchants SET status_active = false WHERE token_number = $1';
                    await client.query(updateQuery, [token]);
                    
                    return res.status(403).json({
                        valid: false,
                        message: 'Trial period has expired. Trial is valid for 7 days only.',
                        data: {
                            token_number: merchant.token_number,
                            register_date: merchant.register_date,
                            trial_expired: true,
                            days_used: Math.floor(daysSinceRegister),
                            max_days: 7
                        }
                    });
                }
            }
            
            // Check if token is active
            if (!merchant.status_active) {
                return res.status(404).json({
                    valid: false,
                    message: 'Token not found or inactive',
                    data: {
                        token_number: merchant.token_number,
                        status_active: false
                    }
                });
            }
            
            return res.json({
                valid: true,
                data: {
                    token_number: merchant.token_number,
                    register_date: merchant.register_date,
                    status_active: merchant.status_active,
                    package: merchant.package,
                    ...(merchant.package === 'trial' ? {
                        trial_days_remaining: Math.max(0, 7 - Math.floor((new Date().getTime() - new Date(merchant.register_date).getTime()) / (1000 * 60 * 60 * 24)))
                    } : {})
                }
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

// Update Device
router.post('/update-device', verifyApiAuth, async (req: Request, res: Response) => {
    const { token, device_id, device_name, device_type } = req.body;

    if (!token || !device_id) {
        return res.status(400).json({ error: 'Token and Device ID are required' });
    }

    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format' });
    }

    if (!isValidDeviceId(device_id)) {
        return res.status(400).json({ error: 'Invalid device ID format' });
    }

    const sanitizedDeviceName = sanitizeString(device_name, 100);
    const sanitizedDeviceType = sanitizeString(device_type, 50);

    let client;
    try {
        client = await pool.connect();

        const checkQuery = 'SELECT token_number, device_id FROM merchants WHERE token_number = $1';
        const checkResult = await client.query(checkQuery, [token]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Token not found' });
        }

        const currentDevice = checkResult.rows[0].device_id;

        if (!currentDevice) {
            const updateQuery = `
                UPDATE merchants 
                SET device_id = $1, device_name = $2, device_type = $3
                WHERE token_number = $4
            `;
            await client.query(updateQuery, [device_id, sanitizedDeviceName, sanitizedDeviceType, token]);

            return res.json({
                success: true,
                message: 'Device registered successfully'
            });

        } else if (currentDevice === device_id) {
            return res.json({
                success: true,
                message: 'Device verified'
            });

        } else {
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

export default router;
