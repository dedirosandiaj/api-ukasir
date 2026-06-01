import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import { encrypt, decrypt } from '../../utils/config';

dotenv.config();

const router = Router();

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// HMAC Signature Verification Middleware (Consistent with notifications.ts / auth.ts)
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

// Input sanitization
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed;
};

// 1. GET /configs (List all configurations)
router.get('/configs', verifyApiAuth, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT key, value, updated_at FROM app_config ORDER BY key ASC';
        const result = await client.query(query);
        
        // Decrypt values for presentation
        const decryptedConfigs = result.rows.map(row => ({
            ...row,
            value: decrypt(row.value)
        }));

        return res.json({
            success: true,
            data: decryptedConfigs
        });
    } catch (error: any) {
        console.error('Get configs error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal Server Error'
        });
    } finally {
        if (client) client.release();
    }
});

// 2. GET /configs/:key (Get a single configuration)
router.get('/configs/:key', verifyApiAuth, async (req: Request, res: Response) => {
    const { key } = req.params;
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT key, value, updated_at FROM app_config WHERE key = $1 LIMIT 1';
        const result = await client.query(query, [key]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Configuration key not found'
            });
        }

        const config = result.rows[0];
        return res.json({
            success: true,
            data: {
                ...config,
                value: decrypt(config.value)
            }
        });
    } catch (error: any) {
        console.error('Get config detail error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal Server Error'
        });
    } finally {
        if (client) client.release();
    }
});

// 3. POST /configs (Create or Update config - Upsert)
router.post('/configs', verifyApiAuth, async (req: Request, res: Response) => {
    const { key, value } = req.body;

    if (!key || value === undefined) {
        return res.status(400).json({
            success: false,
            error: 'Key and value are required'
        });
    }

    const sanitizedKey = sanitizeString(key, 255);
    if (!sanitizedKey) {
        return res.status(400).json({
            success: false,
            error: 'Invalid key'
        });
    }

    let client;
    try {
        const encryptedValue = encrypt(value);
        client = await pool.connect();
        const query = `
            INSERT INTO app_config (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key)
            DO UPDATE SET value = $2, updated_at = NOW()
            RETURNING key, value, updated_at
        `;
        const result = await client.query(query, [sanitizedKey, encryptedValue]);
        const savedConfig = result.rows[0];

        return res.status(200).json({
            success: true,
            message: 'Configuration saved successfully',
            data: {
                ...savedConfig,
                value: decrypt(savedConfig.value)
            }
        });
    } catch (error: any) {
        console.error('Save config error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal Server Error'
        });
    } finally {
        if (client) client.release();
    }
});

// 4. PUT /configs/:key (Update a configuration)
router.put('/configs/:key', verifyApiAuth, async (req: Request, res: Response) => {
    const { key } = req.params;
    const { value } = req.body;

    if (value === undefined) {
        return res.status(400).json({
            success: false,
            error: 'Value is required'
        });
    }

    let client;
    try {
        client = await pool.connect();
        
        // Check if exists
        const checkQuery = 'SELECT key FROM app_config WHERE key = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [key]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Configuration key not found'
            });
        }

        const encryptedValue = encrypt(value);
        const updateQuery = `
            UPDATE app_config
            SET value = $1, updated_at = NOW()
            WHERE key = $2
            RETURNING key, value, updated_at
        `;
        const result = await client.query(updateQuery, [encryptedValue, key]);
        const updatedConfig = result.rows[0];

        return res.json({
            success: true,
            message: 'Configuration updated successfully',
            data: {
                ...updatedConfig,
                value: decrypt(updatedConfig.value)
            }
        });
    } catch (error: any) {
        console.error('Update config error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal Server Error'
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
