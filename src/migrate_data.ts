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

async function migrateData() {
    const client = await pool.connect();
    try {
        console.log('Migrating data from "token_number" to "ukasir_token"...');

        // Select from source table and insert into destination
        // Assumes columns match or map directly
        const insertQuery = `
            INSERT INTO ukasir_token (token_number, register_date, status_active)
            SELECT token_number, register_date, status_active 
            FROM token_number
            ON CONFLICT (token_number) DO NOTHING;
        `;

        const res = await client.query(insertQuery);
        console.log(`Migrated ${res.rowCount} rows.`);
    } catch (err) {
        console.error('Data migration failed:', err);
    } finally {
        client.release();
        pool.end();
    }
}

migrateData();
