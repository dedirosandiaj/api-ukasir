import { Pool } from 'pg';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

async function run() {
    console.log('Testing connection string:', process.env.DATABASE_URL);
    let client;
    try {
        client = await pool.connect();
        console.log('Successfully connected to PG!');
        // Test simple query
        console.log('Testing simple query...');
        const res = await client.query('SELECT NOW()');
        console.log('Query Success! Rows count:', res.rows.length);
        console.log('Rows:', res.rows);
    } catch (e: any) {
        console.error('Database connection or query error:', e.message);
        console.error(e);
    } finally {
        if (client) client.release();
        await pool.end();
    }
}

run();
