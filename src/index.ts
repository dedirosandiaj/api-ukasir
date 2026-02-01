import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/vercel'
import { serve } from '@hono/node-server'
import { Pool } from 'pg'
import * as dotenv from 'dotenv'

dotenv.config()

const app = new Hono().basePath('/api')

app.use('/*', cors())

const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: false
})

// Test connection on startup (optional, good for debugging logs)
pool.connect().then(client => {
    console.log('Connected to Postgres')
    client.release()
}).catch(err => {
    console.error('Failed to connect to Postgres', err)
})

app.get('/', (c) => {
    return c.json({
        message: 'Ukasir Offline API is running',
        version: '1.0.0'
    })
})

app.get('/validate-token', async (c) => {
    const token = c.req.query('token')

    if (!token) {
        return c.json({ error: 'Token is required' }, 400)
    }

    // Basic format validation (9999-0000-1111-2222)
    const tokenRegex = /^\d{4}-\d{4}-\d{4}-\d{4}$/;
    if (!tokenRegex.test(token)) {
        // We can be lenient or strict. User provided example 9999-0000-1111-2222.
        // Let's just warn or allow loose search if they want? 
        // Strict is safer.
    }

    let client;
    try {
        client = await pool.connect()
        // Table found is named "token_number"
        const query = 'SELECT token_number, register_date, status_active FROM token_number WHERE token_number = $1'
        const result = await client.query(query, [token])

        if (result.rows.length > 0) {
            return c.json({
                valid: true,
                data: result.rows[0]
            })
        } else {
            return c.json({
                valid: false,
                message: 'Token not found or inactive'
            }, 404)
        }
    } catch (error: any) {
        console.error('Database error:', error)
        return c.json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        }, 500)
    } finally {
        if (client) client.release()
    }
})

// Local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
    const port = 3000
    console.log(`Server is running on http://localhost:${port}`)
    serve({
        fetch: app.fetch,
        port
    })
}

export default handle(app)
