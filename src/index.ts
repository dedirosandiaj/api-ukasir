import express, { Request, Response } from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

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

app.post('/api/validate-token', async (req: Request, res: Response) => {
    const token = req.body.token;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    // Basic format validation (9999-0000-1111-2222)
    const tokenRegex = /^\d{4}-\d{4}-\d{4}-\d{4}$/;
    // if (!tokenRegex.test(token)) { ... } 

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

app.post('/api/update-device', async (req: Request, res: Response) => {
    const { token, device_id, device_name, device_type } = req.body;

    if (!token || !device_id) {
        return res.status(400).json({ error: 'Token and Device ID are required' });
    }

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
            await client.query(updateQuery, [device_id, device_name, device_type, token]);

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

// Vercel requires exporting the app
export default app;

// Local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}
