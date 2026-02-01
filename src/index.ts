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

// Vercel requires exporting the app
export default app;

// Local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}
