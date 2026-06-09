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

const isValidTokenFormat = (token: any): boolean => {
    if (typeof token !== 'string') return false;
    return /^\d{4}-\d{4}-\d{4}-\d{4}$/.test(token);
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

// Superadmin Authorization Middleware (Consistent with existing routes)
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

// 1. Get Merchant Balance Details (Authenticated clients)
router.get('/withdrawals/balance', verifyApiAuth, async (req: Request, res: Response) => {
    const token_number = req.query.token_number as string;
    let client;

    try {
        if (!token_number) {
            return res.status(400).json({ error: 'token_number query parameter is required' });
        }

        if (!isValidTokenFormat(token_number)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        const sanitizedToken = sanitizeString(token_number, 255);
        if (!sanitizedToken) {
            return res.status(400).json({ error: 'Invalid token data' });
        }

        client = await pool.connect();

        // Verify merchant exists and is active
        const checkMerchant = 'SELECT token_number, status_active FROM merchants WHERE token_number = $1 LIMIT 1';
        const merchantRes = await client.query(checkMerchant, [sanitizedToken]);

        if (merchantRes.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant token not found' });
        }

        if (!merchantRes.rows[0].status_active) {
            return res.status(403).json({ error: 'Merchant account is inactive' });
        }

        // Calculate total earned
        const earnedQuery = `
            SELECT COALESCE(SUM(gross_amount), 0) as total_earned 
            FROM cashier_transactions 
            WHERE token_number = $1 
              AND payment_status IN ('settlement', 'capture', 'paid')
        `;
        const earnedRes = await client.query(earnedQuery, [sanitizedToken]);
        const totalEarned = parseFloat(earnedRes.rows[0].total_earned);

        // Calculate total withdrawn (pending, approved, completed)
        const withdrawnQuery = `
            SELECT COALESCE(SUM(amount), 0) as total_withdrawn 
            FROM withdrawals 
            WHERE token_number = $1 
              AND status IN ('pending', 'approved', 'completed')
        `;
        const withdrawnRes = await client.query(withdrawnQuery, [sanitizedToken]);
        const totalWithdrawn = parseFloat(withdrawnRes.rows[0].total_withdrawn);

        const withdrawableBalance = totalEarned - totalWithdrawn;

        return res.status(200).json({
            success: true,
            data: {
                token_number: sanitizedToken,
                total_earned: totalEarned,
                total_withdrawn: totalWithdrawn,
                withdrawable_balance: withdrawableBalance >= 0 ? withdrawableBalance : 0
            }
        });

    } catch (error: any) {
        console.error('Get merchant balance error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 2. Request Withdrawal (Authenticated clients)
router.post('/withdrawals', verifyApiAuth, async (req: Request, res: Response) => {
    const { token_number, amount } = req.body;
    let client;

    try {
        if (!token_number || amount === undefined || amount === null) {
            return res.status(400).json({ error: 'token_number and amount are required' });
        }

        if (!isValidTokenFormat(token_number)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        const parsedAmount = parseFloat(amount.toString());
        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            return res.status(400).json({ error: 'amount must be a positive number' });
        }

        // Minimum withdrawal limit (e.g., Rp 10.000)
        if (parsedAmount < 10000) {
            return res.status(400).json({ error: 'Batas minimal penarikan adalah Rp 10.000' });
        }

        const sanitizedToken = sanitizeString(token_number, 255);
        if (!sanitizedToken) {
            return res.status(400).json({ error: 'Invalid token data' });
        }

        client = await pool.connect();

        // Start transaction
        await client.query('BEGIN');

        // A. Verify merchant exists, is active and lock the row to prevent concurrent withdrawals
        const checkMerchant = 'SELECT token_number, status_active FROM merchants WHERE token_number = $1 LIMIT 1 FOR UPDATE';
        const merchantRes = await client.query(checkMerchant, [sanitizedToken]);

        if (merchantRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Merchant token not found' });
        }

        if (!merchantRes.rows[0].status_active) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Merchant account is inactive' });
        }

        // B. Get bank details from approved QRIS activation
        const checkQris = `
            SELECT account_name, account_name_owner, account_number_owner 
            FROM qris_activations 
            WHERE token_number = $1 AND status = 'approved' 
            ORDER BY created_at DESC 
            LIMIT 1
        `;
        const qrisRes = await client.query(checkQris, [sanitizedToken]);

        if (qrisRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(403).json({ 
                error: 'Metode penarikan tidak tersedia. Harap pastikan aktivasi QRIS Anda telah disetujui untuk mendaftarkan rekening tujuan.' 
            });
        }

        const bankInfo = qrisRes.rows[0];

        // C. Calculate current withdrawable balance inside transaction
        const earnedQuery = `
            SELECT COALESCE(SUM(gross_amount), 0) as total_earned 
            FROM cashier_transactions 
            WHERE token_number = $1 
              AND payment_status IN ('settlement', 'capture', 'paid')
        `;
        const earnedRes = await client.query(earnedQuery, [sanitizedToken]);
        const totalEarned = parseFloat(earnedRes.rows[0].total_earned);

        const withdrawnQuery = `
            SELECT COALESCE(SUM(amount), 0) as total_withdrawn 
            FROM withdrawals 
            WHERE token_number = $1 
              AND status IN ('pending', 'approved', 'completed')
        `;
        const withdrawnRes = await client.query(withdrawnQuery, [sanitizedToken]);
        const totalWithdrawn = parseFloat(withdrawnRes.rows[0].total_withdrawn);

        const withdrawableBalance = totalEarned - totalWithdrawn;

        if (parsedAmount > withdrawableBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                error: `Saldo tidak mencukupi. Saldo yang dapat ditarik saat ini: Rp ${withdrawableBalance.toLocaleString('id-ID')}` 
            });
        }

        // D. Insert withdrawal request
        const insertQuery = `
            INSERT INTO withdrawals (
                id, token_number, amount, status, bank_name, account_number, account_name, created_at, updated_at
            )
            VALUES (gen_random_uuid(), $1, $2, 'pending', $3, $4, $5, NOW(), NOW())
            RETURNING *
        `;
        const result = await client.query(insertQuery, [
            sanitizedToken,
            parsedAmount,
            bankInfo.account_name,
            bankInfo.account_number_owner,
            bankInfo.account_name_owner
        ]);

        await client.query('COMMIT');

        return res.status(201).json({
            success: true,
            message: 'Permintaan penarikan dana berhasil diajukan dan sedang diproses.',
            data: result.rows[0]
        });

    } catch (error: any) {
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rbErr) {
                console.error('Rollback error:', rbErr);
            }
        }
        console.error('Request withdrawal error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 3. Get Withdrawal Requests History (Authenticated clients / Superadmin)
router.get('/withdrawals', verifyApiAuth, async (req: Request, res: Response) => {
    const { token_number, page, limit, status, search } = req.query;
    const role = req.headers['x-role'] as string;
    const superadminSecret = req.headers['x-superadmin-secret'] as string;
    const envSecret = process.env.SUPERADMIN_SECRET;

    const isSuperAdmin = role === 'superadmin' || (envSecret && superadminSecret === envSecret);
    let client;

    try {
        client = await pool.connect();

        if (isSuperAdmin) {
            // Superadmin view: list all/filtered withdrawals with pagination and join on merchants
            const pageNum = parseInt(page as string) || 1;
            const limitNum = parseInt(limit as string) || 20;
            const offset = (pageNum - 1) * limitNum;

            let whereConditions: string[] = [];
            let queryParams: any[] = [];
            let paramIndex = 1;

            if (status) {
                whereConditions.push(`w.status = $${paramIndex}`);
                queryParams.push(status);
                paramIndex++;
            }

            if (token_number) {
                whereConditions.push(`w.token_number = $${paramIndex}`);
                queryParams.push(token_number);
                paramIndex++;
            }

            if (search) {
                whereConditions.push(`(
                    w.token_number ILIKE $${paramIndex} OR 
                    w.bank_name ILIKE $${paramIndex} OR 
                    w.account_number ILIKE $${paramIndex} OR 
                    w.account_name ILIKE $${paramIndex} OR
                    m.merchant_name ILIKE $${paramIndex} OR
                    m.name ILIKE $${paramIndex}
                )`);
                queryParams.push(`%${search}%`);
                paramIndex++;
            }

            const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

            // Get total count
            const countQuery = `
                SELECT COUNT(*) 
                FROM withdrawals w
                LEFT JOIN merchants m ON w.token_number = m.token_number
                ${whereClause}
            `;
            const countResult = await client.query(countQuery, queryParams);
            const total = parseInt(countResult.rows[0].count);

            // Get details
            const dataQuery = `
                SELECT 
                    w.id,
                    w.token_number,
                    w.amount,
                    w.status,
                    w.bank_name,
                    w.account_number,
                    w.account_name,
                    w.reason,
                    w.created_at,
                    w.updated_at,
                    m.name as merchant_owner_name,
                    m.merchant_name as merchant_name
                FROM withdrawals w
                LEFT JOIN merchants m ON w.token_number = m.token_number
                ${whereClause}
                ORDER BY w.created_at DESC
                LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
            `;

            queryParams.push(limitNum, offset);
            const dataResult = await client.query(dataQuery, queryParams);

            const totalPages = Math.ceil(total / limitNum);

            return res.status(200).json({
                success: true,
                message: 'Withdrawal requests retrieved successfully',
                data: dataResult.rows,
                pagination: {
                    current_page: pageNum,
                    per_page: limitNum,
                    total_items: total,
                    total_pages: totalPages,
                    has_next: pageNum < totalPages,
                    has_prev: pageNum > 1
                }
            });
        } else {
            // Regular merchant view: require token_number
            if (!token_number) {
                return res.status(400).json({ error: 'token_number query parameter is required' });
            }

            if (!isValidTokenFormat(token_number)) {
                return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
            }

            const sanitizedToken = sanitizeString(token_number, 255);
            if (!sanitizedToken) {
                return res.status(400).json({ error: 'Invalid token data' });
            }

            const query = 'SELECT * FROM withdrawals WHERE token_number = $1 ORDER BY created_at DESC LIMIT 100';
            const result = await client.query(query, [sanitizedToken]);

            return res.status(200).json({
                success: true,
                data: result.rows
            });
        }

    } catch (error: any) {
        console.error('Get withdrawals history error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 4. Update Withdrawal Status (Superadmin only)
router.put('/withdrawals/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { status, reason } = req.body;
    let client;

    try {
        if (!status) {
            return res.status(400).json({ error: 'Status is required' });
        }

        if (status !== 'pending' && status !== 'approved' && status !== 'rejected' && status !== 'completed') {
            return res.status(400).json({ 
                error: 'Invalid status. Allowed values: pending, approved, rejected, completed' 
            });
        }

        if (status === 'rejected' && !reason) {
            return res.status(400).json({ error: 'Reason is required when status is rejected' });
        }

        client = await pool.connect();

        // Check if withdrawal exists
        const checkQuery = 'SELECT * FROM withdrawals WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Withdrawal request not found' });
        }

        // Update status and reason
        const updateQuery = `
            UPDATE withdrawals
            SET status = $1, reason = $2, updated_at = NOW()
            WHERE id = $3::uuid
            RETURNING *
        `;
        const result = await client.query(updateQuery, [status, reason || null, id]);

        return res.status(200).json({
            success: true,
            message: 'Status penarikan dana berhasil diperbarui.',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update withdrawal status error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
