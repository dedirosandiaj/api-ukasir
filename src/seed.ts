import { Pool } from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function seed() {
    const client = await pool.connect();
    try {
        console.log('Seeding database...');

        // Sample token requested by user previously
        const query = `
            INSERT INTO ukasir_token (token_number, register_date, status_active)
            VALUES ($1, NOW(), true)
            ON CONFLICT (token_number) DO NOTHING
            RETURNING *;
        `;

        const values = ['9999-0000-1111-2222'];
        const res = await client.query(query, values);

        if (res.rowCount && res.rowCount > 0) {
            console.log('Seeded token:', res.rows[0].token_number);
        } else {
            console.log('Token already exists, skipped.');
        }

    } catch (err) {
        console.error('Seeding failed:', err);
    } finally {
        client.release();
        pool.end();
    }
}

seed();
