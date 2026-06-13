import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import * as googleTTS from 'google-tts-api';
import angkaMenjadiTerbilang from 'angka-menjadi-terbilang';

dotenv.config();

const router = Router();

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// HMAC Authentication Middleware
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

// GET sound settings for a merchant
router.get('/sounds/settings/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT is_sound_enabled FROM merchants WHERE token_number = $1 LIMIT 1';
        const result = await client.query(query, [token]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        return res.status(200).json({
            success: true,
            message: 'Sound settings retrieved',
            data: {
                is_sound_enabled: result.rows[0].is_sound_enabled
            }
        });
    } catch (error: any) {
        console.error('Get sound settings error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// UPDATE sound settings for a merchant
router.put('/sounds/settings/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    const { is_sound_enabled } = req.body;
    
    if (typeof is_sound_enabled !== 'boolean') {
        return res.status(400).json({ error: 'is_sound_enabled must be a boolean' });
    }

    let client;
    try {
        client = await pool.connect();
        const updateQuery = 'UPDATE merchants SET is_sound_enabled = $1, updated_at = NOW() WHERE token_number = $2 RETURNING is_sound_enabled';
        const result = await client.query(updateQuery, [is_sound_enabled, token]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        return res.status(200).json({
            success: true,
            message: 'Sound settings updated',
            data: {
                is_sound_enabled: result.rows[0].is_sound_enabled
            }
        });
    } catch (error: any) {
        console.error('Update sound settings error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// POST Generate Payment Success Sound
router.post('/sounds/payment-success/:token', verifyApiAuth, async (req: Request, res: Response) => {
    const { token } = req.params;
    const { amount } = req.body;

    if (amount === undefined || amount === null) {
        return res.status(400).json({ error: 'Amount is required' });
    }

    let client;
    try {
        client = await pool.connect();
        // Check if sound is enabled
        const checkQuery = 'SELECT is_sound_enabled FROM merchants WHERE token_number = $1 LIMIT 1';
        const result = await client.query(checkQuery, [token]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        if (!result.rows[0].is_sound_enabled) {
            return res.status(400).json({ error: 'Sound is disabled for this merchant' });
        }

        // Generate text
        const amountNumber = parseFloat(amount.toString());
        const terbilangStr = angkaMenjadiTerbilang(amountNumber);
        const text = `Pembayaran sebesar ${terbilangStr} rupiah, berhasil`;

        // Get audio URL from google-tts-api
        const url = googleTTS.getAudioUrl(text, {
            lang: 'id',
            slow: false,
            host: 'https://translate.google.com',
        });

        // Get base64 (optional, but let's provide URL and base64)
        const base64 = await googleTTS.getAudioBase64(text, {
            lang: 'id',
            slow: false,
            host: 'https://translate.google.com',
            timeout: 10000,
        });

        return res.status(200).json({
            success: true,
            message: 'Audio generated successfully',
            data: {
                url,
                base64,
                text
            }
        });
    } catch (error: any) {
        console.error('Generate sound error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
