import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const router = Router();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// PONYTAIL MODE: Ultra lazy, minimum abstraction, maximum performance.

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

router.get('/regions/provinces', verifyApiAuth, async (req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT id, name FROM provinces ORDER BY name ASC');
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/cities', verifyApiAuth, async (req: Request, res: Response) => {
    const { province_id } = req.query;
    if (!province_id) return res.status(400).json({ success: false, error: 'province_id is required' });

    try {
        const result = await pool.query('SELECT id, name FROM regencies WHERE province_id = $1 ORDER BY name ASC', [province_id]);
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/districts', verifyApiAuth, async (req: Request, res: Response) => {
    const { city_id } = req.query;
    if (!city_id) return res.status(400).json({ success: false, error: 'city_id is required' });

    try {
        const result = await pool.query('SELECT id, name FROM districts WHERE regency_id = $1 ORDER BY name ASC', [city_id]);
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/villages', verifyApiAuth, async (req: Request, res: Response) => {
    const { district_id } = req.query;
    if (!district_id) return res.status(400).json({ success: false, error: 'district_id is required' });

    try {
        const result = await pool.query('SELECT id, name, postal_code FROM villages WHERE district_id = $1 ORDER BY name ASC', [district_id]);
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

export default router;
