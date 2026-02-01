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

const createTableQuery = `
    CREATE TABLE IF NOT EXISTS ukasir_token (
        token_number VARCHAR(255) PRIMARY KEY,
        register_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status_active BOOLEAN DEFAULT TRUE
    );
`;

async function migrate() {
    try {
        console.log('Connecting to database...');
        const client = await pool.connect();
        console.log('Running migration...');
        await client.query(createTableQuery);
        console.log('Table "ukasir_token" created successfully!');
        client.release();
    } catch (err) {
        console.error('Migration failed:', err);
    } finally {
        pool.end();
    }
}

migrate();
