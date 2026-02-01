import { Pool } from 'pg'
import * as dotenv from 'dotenv'

dotenv.config()

const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: false
})

async function checkTables() {
    const client = await pool.connect()
    try {
        const dbRes = await client.query('SELECT current_database(), current_user');
        console.log(`Connected to DB: ${dbRes.rows[0].current_database} as ${dbRes.rows[0].current_user}`);
        const res = await client.query(`
      SELECT table_name, column_name, data_type 
      FROM information_schema.columns 
      WHERE table_schema = 'public' 
      ORDER BY table_name, ordinal_position
    `)
        console.log('Columns found:')
        res.rows.forEach(row => console.log(`${row.table_name}: ${row.column_name} (${row.data_type})`))
    } catch (err) {
        console.error('Error listing tables:', err)
    } finally {
        client.release()
        pool.end()
    }
}

checkTables()
