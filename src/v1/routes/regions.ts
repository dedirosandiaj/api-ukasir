import { Router, Request, Response } from 'express';
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

router.get('/regions/provinces', async (req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT id, name FROM provinces ORDER BY name ASC');
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/cities', async (req: Request, res: Response) => {
    const { province_id } = req.query;
    if (!province_id) return res.status(400).json({ success: false, error: 'province_id is required' });

    try {
        const result = await pool.query('SELECT id, name FROM regencies WHERE province_id = $1 ORDER BY name ASC', [province_id]);
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/districts', async (req: Request, res: Response) => {
    const { city_id } = req.query;
    if (!city_id) return res.status(400).json({ success: false, error: 'city_id is required' });

    try {
        const result = await pool.query('SELECT id, name FROM districts WHERE regency_id = $1 ORDER BY name ASC', [city_id]);
        return res.status(200).json({ success: true, data: result.rows });
    } catch (err: any) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

router.get('/regions/villages', async (req: Request, res: Response) => {
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
