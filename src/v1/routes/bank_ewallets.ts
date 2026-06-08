import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const router = Router();

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// Input sanitization
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed.replace(/[<>\"']/g, '');
};

// HMAC Signature Verification Middleware (Consistent with existing routes)
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

// Superadmin Authorization Middleware
const verifySuperAdmin = (req: Request, res: Response, next: NextFunction): void => {
    const role = req.headers['x-role'] as string;
    const superadminSecret = req.headers['x-superadmin-secret'] as string;
    const envSecret = process.env.SUPERADMIN_SECRET;

    const isSuperAdminRole = role === 'superadmin';
    const isValidSecret = envSecret && superadminSecret === envSecret;

    if (isSuperAdminRole || isValidSecret) {
        next();
    } else {
        res.status(403).json({ error: 'Access denied. Superadmin permission required.' });
    }
};

// 1. Get All Bank & E-Wallet Accounts (Authenticated users)
router.get('/bank-ewallets', verifyApiAuth, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const type = req.query.type as string; // 'bank' or 'e-wallet'
        const search = req.query.search as string;

        const offset = (page - 1) * limit;

        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (type) {
            whereConditions.push(`account_type = $${paramIndex}`);
            queryParams.push(type);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`account_name ILIKE $${paramIndex}`);
            queryParams.push(`%${search}%`);
            paramIndex++;
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

        // Get count
        const countQuery = `SELECT COUNT(*) FROM bank_ewallets ${whereClause}`;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        // Get data
        const dataQuery = `
            SELECT id, account_name, account_type, created_at, updated_at
            FROM bank_ewallets
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.status(200).json({
            success: true,
            message: 'Accounts retrieved successfully',
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
        console.error('Get bank_ewallets error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 2. Get Bank & E-Wallet Account by ID (Authenticated users)
router.get('/bank-ewallets/:id', verifyApiAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT * FROM bank_ewallets WHERE id = $1::uuid LIMIT 1';
        const result = await client.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }

        return res.status(200).json({
            success: true,
            message: 'Account retrieved successfully',
            data: result.rows[0]
        });
    } catch (error: any) {
        console.error('Get bank_ewallet detail error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 3. Create Bank & E-Wallet Account (Superadmin only)
router.post('/bank-ewallets', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { account_name, account_type } = req.body;
    let client;

    try {
        if (!account_name || !account_type) {
            return res.status(400).json({ error: 'account_name and account_type are required' });
        }

        const sanitizedName = sanitizeString(account_name, 255);
        const sanitizedType = sanitizeString(account_type, 50);

        if (!sanitizedName || !sanitizedType) {
            return res.status(400).json({ error: 'Invalid name or type input' });
        }

        if (sanitizedType !== 'bank' && sanitizedType !== 'e-wallet') {
            return res.status(400).json({ error: 'account_type must be either bank or e-wallet' });
        }

        client = await pool.connect();

        const query = `
            INSERT INTO bank_ewallets (id, account_name, account_type)
            VALUES (gen_random_uuid(), $1, $2)
            RETURNING *
        `;

        const result = await client.query(query, [sanitizedName, sanitizedType]);

        return res.status(201).json({
            success: true,
            message: 'Account created successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Create bank_ewallet error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 4. Update Bank & E-Wallet Account (Superadmin only)
router.put('/bank-ewallets/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { account_name, account_type } = req.body;
    let client;

    try {
        client = await pool.connect();

        // Check if exists
        const checkQuery = 'SELECT * FROM bank_ewallets WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }

        const existing = checkResult.rows[0];

        const sanitizedName = account_name !== undefined ? sanitizeString(account_name, 255) : existing.account_name;
        const sanitizedType = account_type !== undefined ? sanitizeString(account_type, 50) : existing.account_type;

        if (!sanitizedName || !sanitizedType) {
            return res.status(400).json({ error: 'Name and type cannot be empty' });
        }

        if (sanitizedType !== 'bank' && sanitizedType !== 'e-wallet') {
            return res.status(400).json({ error: 'account_type must be either bank or e-wallet' });
        }

        const updateQuery = `
            UPDATE bank_ewallets SET
                account_name = $1,
                account_type = $2,
                updated_at = NOW()
            WHERE id = $3::uuid
            RETURNING *
        `;

        const result = await client.query(updateQuery, [sanitizedName, sanitizedType, id]);

        return res.status(200).json({
            success: true,
            message: 'Account updated successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update bank_ewallet error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 5. Delete Bank & E-Wallet Account (Superadmin only)
router.delete('/bank-ewallets/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();

        const checkQuery = 'SELECT id FROM bank_ewallets WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }

        const deleteQuery = 'DELETE FROM bank_ewallets WHERE id = $1::uuid RETURNING *';
        const result = await client.query(deleteQuery, [id]);

        return res.status(200).json({
            success: true,
            message: 'Account deleted successfully',
            data: result.rows[0]
        });
    } catch (error: any) {
        console.error('Delete bank_ewallet error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
