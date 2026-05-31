import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const router = Router();

// Rate limiting for client endpoint (fetching notifications)
const clientNotificationLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute
    message: { error: 'Too many notification requests, please try again later.' }
});

// Database connection
const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// Input sanitization helpers
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed.replace(/[<>\"']/g, '');
};

const sanitizeText = (input: any, maxLength: number = 5000): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed;
};

const isValidTokenFormat = (token: any): boolean => {
    if (typeof token !== 'string') return false;
    return /^\d{4}-\d{4}-\d{4}-\d{4}$/.test(token);
};

// HMAC Signature Verification Middleware (Consistent with products.ts / token.ts)
const verifyApiAuth = (req: Request, res: Response, next: NextFunction): void => {
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

// ==========================================
// ADMIN ENDPOINTS (CRUD & SCHEDULING)
// ==========================================

// 1. Create Notification
router.post('/notifications', verifyApiAuth, async (req: Request, res: Response) => {
    const { title, body, type, target_type, token_number, status, scheduled_at } = req.body;
    let client;

    try {
        if (!title || !body) {
            return res.status(400).json({ error: 'Title and body are required' });
        }

        const sanitizedTitle = sanitizeString(title, 255);
        const sanitizedBody = sanitizeText(body, 5000);
        const sanitizedType = sanitizeString(type, 50) || 'info';
        const sanitizedTargetType = sanitizeString(target_type, 50) || 'broadcast';
        const sanitizedToken = token_number ? sanitizeString(token_number, 255) : null;
        const sanitizedStatus = sanitizeString(status, 50) || 'scheduled';
        const parsedScheduledAt = scheduled_at ? new Date(scheduled_at) : new Date();

        if (!sanitizedTitle || !sanitizedBody) {
            return res.status(400).json({ error: 'Invalid title or body' });
        }

        if (sanitizedTargetType === 'targeted' && !sanitizedToken) {
            return res.status(400).json({ error: 'token_number is required for targeted notifications' });
        }

        if (sanitizedToken && !isValidTokenFormat(sanitizedToken)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        client = await pool.connect();

        // If targeted, verify token exists
        if (sanitizedTargetType === 'targeted' && sanitizedToken) {
            const checkMerchant = 'SELECT token_number FROM merchants WHERE token_number = $1';
            const merchantRes = await client.query(checkMerchant, [sanitizedToken]);
            if (merchantRes.rows.length === 0) {
                return res.status(404).json({ error: 'Target merchant token not found' });
            }
        }

        const query = `
            INSERT INTO notifications (id, title, body, type, target_type, token_number, status, scheduled_at)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `;

        const result = await client.query(query, [
            sanitizedTitle,
            sanitizedBody,
            sanitizedType,
            sanitizedTargetType,
            sanitizedToken,
            sanitizedStatus,
            parsedScheduledAt
        ]);

        return res.status(201).json({
            success: true,
            message: 'Notification created successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Create notification error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 2. Get All Notifications (Admin view)
router.get('/notifications', verifyApiAuth, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const type = req.query.type as string;
        const status = req.query.status as string;
        const search = req.query.search as string;

        const offset = (page - 1) * limit;

        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (type) {
            whereConditions.push(`type = $${paramIndex}`);
            queryParams.push(type);
            paramIndex++;
        }

        if (status) {
            whereConditions.push(`status = $${paramIndex}`);
            queryParams.push(status);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`(title ILIKE $${paramIndex} OR body ILIKE $${paramIndex})`);
            queryParams.push(`%${search}%`);
            paramIndex++;
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

        const countQuery = `SELECT COUNT(*) FROM notifications ${whereClause}`;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        const dataQuery = `
            SELECT * FROM notifications
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.json({
            success: true,
            data: dataResult.rows,
            pagination: {
                current_page: page,
                per_page: limit,
                total_items: total,
                total_pages: totalPages,
                has_next: page < totalPages,
                has_prev: page > 1
            }
        });

    } catch (error: any) {
        console.error('Get notifications error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 3. Get Notification by ID
router.get('/notifications/:id', verifyApiAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT * FROM notifications WHERE id = $1::uuid LIMIT 1';
        const result = await client.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        return res.json({
            success: true,
            data: result.rows[0]
        });
    } catch (error: any) {
        console.error('Get notification detail error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 4. Update Notification
router.put('/notifications/:id', verifyApiAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { title, body, type, target_type, token_number, status, scheduled_at } = req.body;
    let client;

    try {
        client = await pool.connect();

        // Check if exists
        const checkQuery = 'SELECT * FROM notifications WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        const existing = checkResult.rows[0];

        const sanitizedTitle = title !== undefined ? sanitizeString(title, 255) : existing.title;
        const sanitizedBody = body !== undefined ? sanitizeText(body, 5000) : existing.body;
        const sanitizedType = type !== undefined ? sanitizeString(type, 50) : existing.type;
        const sanitizedTargetType = target_type !== undefined ? sanitizeString(target_type, 50) : existing.target_type;
        const sanitizedToken = token_number !== undefined ? (token_number ? sanitizeString(token_number, 255) : null) : existing.token_number;
        const sanitizedStatus = status !== undefined ? sanitizeString(status, 50) : existing.status;
        const parsedScheduledAt = scheduled_at !== undefined ? new Date(scheduled_at) : existing.scheduled_at;

        if (!sanitizedTitle || !sanitizedBody) {
            return res.status(400).json({ error: 'Title and body cannot be empty' });
        }

        if (sanitizedTargetType === 'targeted' && !sanitizedToken) {
            return res.status(400).json({ error: 'token_number is required for targeted notifications' });
        }

        if (sanitizedToken && !isValidTokenFormat(sanitizedToken)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        // If targeted, verify token exists
        if (sanitizedTargetType === 'targeted' && sanitizedToken) {
            const checkMerchant = 'SELECT token_number FROM merchants WHERE token_number = $1';
            const merchantRes = await client.query(checkMerchant, [sanitizedToken]);
            if (merchantRes.rows.length === 0) {
                return res.status(404).json({ error: 'Target merchant token not found' });
            }
        }

        const updateQuery = `
            UPDATE notifications SET
                title = $1,
                body = $2,
                type = $3,
                target_type = $4,
                token_number = $5,
                status = $6,
                scheduled_at = $7,
                updated_at = NOW()
            WHERE id = $8::uuid
            RETURNING *
        `;

        const result = await client.query(updateQuery, [
            sanitizedTitle,
            sanitizedBody,
            sanitizedType,
            sanitizedTargetType,
            sanitizedToken,
            sanitizedStatus,
            parsedScheduledAt,
            id
        ]);

        return res.json({
            success: true,
            message: 'Notification updated successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update notification error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 5. Delete Notification
router.delete('/notifications/:id', verifyApiAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();

        const checkQuery = 'SELECT id FROM notifications WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        // Delete from reads first (foreign key/cascading reference)
        await client.query('DELETE FROM notification_reads WHERE notification_id = $1::uuid', [id]);
        
        // Delete notification
        await client.query('DELETE FROM notifications WHERE id = $1::uuid', [id]);

        return res.json({
            success: true,
            message: 'Notification deleted successfully'
        });
    } catch (error: any) {
        console.error('Delete notification error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// CLIENT ENDPOINTS (MERCHANT APP)
// ==========================================

// 6. Get Merchant Notifications (Retrieves active notifications and read status)
router.get('/merchant/notifications', verifyApiAuth, clientNotificationLimiter, async (req: Request, res: Response) => {
    const token = req.query.token as string;
    let client;

    if (!token) {
        return res.status(400).json({ error: 'Merchant token is required' });
    }

    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format' });
    }

    try {
        client = await pool.connect();

        // 1. Verify merchant exists and is active
        const checkMerchant = 'SELECT token_number, status_active FROM merchants WHERE token_number = $1 LIMIT 1';
        const merchantRes = await client.query(checkMerchant, [token]);

        if (merchantRes.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant token not found' });
        }

        if (!merchantRes.rows[0].status_active) {
            return res.status(403).json({ error: 'Merchant account is inactive' });
        }

        // 2. Query active notifications (scheduled_at <= NOW and status = scheduled)
        // Check if targeted to this token OR broadcast to all.
        // Include is_read flag by checking notification_reads table.
        const query = `
            SELECT 
                n.id,
                n.title,
                n.body,
                n.type,
                n.target_type,
                n.scheduled_at,
                n.created_at,
                CASE 
                    WHEN r.read_at IS NOT NULL THEN true 
                    ELSE false 
                END as is_read
            FROM notifications n
            LEFT JOIN notification_reads r 
                ON n.id = r.notification_id AND r.token_number = $1
            WHERE 
                n.status IN ('scheduled', 'sent')
                AND n.scheduled_at <= NOW()
                AND (
                    n.target_type = 'broadcast' 
                    OR (n.target_type = 'targeted' AND n.token_number = $1)
                )
            ORDER BY n.scheduled_at DESC
        `;

        const result = await client.query(query, [token]);

        return res.json({
            success: true,
            message: 'Notifications retrieved successfully',
            data: result.rows
        });

    } catch (error: any) {
        console.error('Merchant get notifications error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 7. Mark Notification as Read
router.post('/merchant/notifications/:id/read', verifyApiAuth, clientNotificationLimiter, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { token } = req.body;
    let client;

    if (!token) {
        return res.status(400).json({ error: 'Merchant token is required' });
    }

    if (!isValidTokenFormat(token)) {
        return res.status(400).json({ error: 'Invalid token format' });
    }

    try {
        client = await pool.connect();

        // 1. Verify merchant exists and is active
        const checkMerchant = 'SELECT token_number, status_active FROM merchants WHERE token_number = $1 LIMIT 1';
        const merchantRes = await client.query(checkMerchant, [token]);

        if (merchantRes.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant token not found' });
        }

        if (!merchantRes.rows[0].status_active) {
            return res.status(403).json({ error: 'Merchant account is inactive' });
        }

        // 2. Verify notification exists and is active/published
        const checkNotif = `
            SELECT id FROM notifications 
            WHERE id = $1::uuid 
              AND status IN ('scheduled', 'sent')
              AND scheduled_at <= NOW()
              AND (target_type = 'broadcast' OR token_number = $2)
            LIMIT 1
        `;
        const notifRes = await client.query(checkNotif, [id, token]);

        if (notifRes.rows.length === 0) {
            return res.status(404).json({ error: 'Active notification not found or not accessible' });
        }

        // 3. Mark as read (INSERT IGNORE / upsert)
        const readQuery = `
            INSERT INTO notification_reads (id, notification_id, token_number, read_at)
            VALUES (gen_random_uuid(), $1::uuid, $2, NOW())
            ON CONFLICT (notification_id, token_number) DO NOTHING
            RETURNING *
        `;

        await client.query(readQuery, [id, token]);

        return res.json({
            success: true,
            message: 'Notification marked as read successfully'
        });

    } catch (error: any) {
        console.error('Mark notification read error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
