import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
// @ts-ignore
import midtransClient from 'midtrans-client';
import { getConfig } from '../../utils/config';

dotenv.config();

const router = Router();

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// Dynamic Midtrans CoreApi Constructor
const getMidtransCore = async () => {
    const serverKey = await getConfig('MIDTRANS_SERVER_KEY');
    const clientKey = await getConfig('MIDTRANS_CLIENT_KEY');
    const isProduction = await getConfig('MIDTRANS_IS_PRODUCTION') === 'true';
    return new midtransClient.CoreApi({
        isProduction,
        serverKey,
        clientKey
    });
};

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


// 1. Create Cashier QRIS Transaction (Authenticated clients)
router.post('/cashier-transactions', verifyApiAuth, async (req: Request, res: Response) => {
    const { token_number, gross_amount } = req.body;
    let client;

    try {
        if (!token_number || gross_amount === undefined || gross_amount === null) {
            return res.status(400).json({ error: 'token_number and gross_amount are required' });
        }

        if (!isValidTokenFormat(token_number)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        const parsedAmount = parseFloat(gross_amount.toString());
        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            return res.status(400).json({ error: 'gross_amount must be a positive number' });
        }

        const sanitizedToken = sanitizeString(token_number, 255);
        if (!sanitizedToken) {
            return res.status(400).json({ error: 'Invalid token data' });
        }

        client = await pool.connect();

        // A. Verify merchant exists and is active
        const checkMerchant = 'SELECT token_number, status_active FROM merchants WHERE token_number = $1 LIMIT 1';
        const merchantRes = await client.query(checkMerchant, [sanitizedToken]);

        if (merchantRes.rows.length === 0) {
            return res.status(404).json({ error: 'Merchant token not found' });
        }

        if (!merchantRes.rows[0].status_active) {
            return res.status(403).json({ error: 'Merchant account is inactive' });
        }

        // B. Verify QRIS is activated for this merchant
        const checkQris = "SELECT status FROM qris_activations WHERE token_number = $1 AND status = 'approved' LIMIT 1";
        const qrisRes = await client.query(checkQris, [sanitizedToken]);

        if (qrisRes.rows.length === 0) {
            return res.status(403).json({ 
                error: 'Metode pembayaran QRIS belum diaktifkan untuk toko Anda. Silakan ajukan aktivasi terlebih dahulu.' 
            });
        }

        // C. Generate unique order ID prefix TRX-
        const orderId = `TRX-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;

        // D. Request QRIS Charge from Midtrans Core API
        const core = await getMidtransCore();
        const midtransPayload = {
            payment_type: 'qris',
            qris: {
                acquirer: 'gopay'
            },
            transaction_details: {
                order_id: orderId,
                gross_amount: parsedAmount
            }
        };

        const chargeResponse = await core.charge(midtransPayload);

        // E. Save transaction details to database
        const query = `
            INSERT INTO cashier_transactions (id, order_id, token_number, gross_amount, payment_status)
            VALUES (gen_random_uuid(), $1, $2, $3, 'pending')
            RETURNING *
        `;
        const result = await client.query(query, [orderId, sanitizedToken, parsedAmount]);

        // F. Extract QR data from actions array
        const actions = chargeResponse.actions || [];
        const qrImageAction = actions.find((a: any) => a.name === 'generate-qr-code');
        const qrImageUrl = qrImageAction ? qrImageAction.url : null;
        const qrData = chargeResponse.qr_string || null;

        return res.status(201).json({
            success: true,
            message: 'Cashier transaction created successfully',
            data: {
                order_id: result.rows[0].order_id,
                gross_amount: result.rows[0].gross_amount,
                payment_status: result.rows[0].payment_status,
                qr_data: qrData,
                qr_image_url: qrImageUrl,
                actions: actions,
                created_at: result.rows[0].created_at
            }
        });

    } catch (error: any) {
        console.error('Create cashier transaction error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 2. Get Transaction Status (Authenticated clients)
router.get('/cashier-transactions/:order_id', verifyApiAuth, async (req: Request, res: Response) => {
    const { order_id } = req.params;
    let client;

    try {
        client = await pool.connect();
        const query = 'SELECT * FROM cashier_transactions WHERE order_id = $1 LIMIT 1';
        const result = await client.query(query, [order_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        return res.status(200).json({
            success: true,
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Get cashier transaction status error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 3. Cancel Cashier Transaction (Authenticated clients)
router.post('/cashier-transactions/:order_id/cancel', verifyApiAuth, async (req: Request, res: Response) => {
    const { order_id } = req.params;
    const { token_number } = req.body;
    let client;

    try {
        if (!token_number) {
            return res.status(400).json({ error: 'token_number is required in request body' });
        }

        if (!isValidTokenFormat(token_number)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        const sanitizedToken = sanitizeString(token_number, 255);
        if (!sanitizedToken) {
            return res.status(400).json({ error: 'Invalid token data' });
        }

        client = await pool.connect();

        // Check if transaction exists and belongs to this token
        const checkQuery = 'SELECT * FROM cashier_transactions WHERE order_id = $1 AND token_number = $2 LIMIT 1';
        const checkRes = await client.query(checkQuery, [order_id, sanitizedToken]);

        if (checkRes.rows.length === 0) {
            return res.status(404).json({ error: 'Transaction not found or token mismatch' });
        }

        const tx = checkRes.rows[0];
        const status = tx.payment_status;

        // If already paid, reject cancel
        if (status === 'settlement' || status === 'capture' || status === 'paid') {
            return res.status(400).json({ 
                error: 'Transaksi sudah berhasil dibayar dan tidak dapat dibatalkan.' 
            });
        }

        // Try to cancel in Midtrans first
        try {
            const core = await getMidtransCore();
            await core.transaction.cancel(order_id);
        } catch (midtransError: any) {
            // Log warning but don't block DB deletion (in case it is already expired/cancelled on Midtrans side)
            console.warn(`Midtrans cancel failed for ${order_id}:`, midtransError.message || midtransError);
        }

        // Delete from local database
        const deleteQuery = 'DELETE FROM cashier_transactions WHERE order_id = $1 AND token_number = $2';
        await client.query(deleteQuery, [order_id, sanitizedToken]);

        return res.status(200).json({
            success: true,
            message: 'Transaction cancelled and removed from database successfully'
        });

    } catch (error: any) {
        console.error('Cancel cashier transaction error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 4. Get Cashier Transactions List by token_number (Authenticated clients)
router.get('/cashier-transactions', verifyApiAuth, async (req: Request, res: Response) => {
    const { token_number } = req.query;
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
        
        // Fetch last 100 transactions for this merchant token
        const query = 'SELECT * FROM cashier_transactions WHERE token_number = $1 ORDER BY created_at DESC LIMIT 100';
        const result = await client.query(query, [sanitizedToken]);

        return res.status(200).json({
            success: true,
            data: result.rows
        });

    } catch (error: any) {
        console.error('Get cashier transactions list error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 5. Get All Cashier Transactions (Superadmin only)
router.get('/transactions', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const offset = (page - 1) * limit;

        const { search, merchant_name, payment_status, token_number } = req.query;

        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (payment_status) {
            whereConditions.push(`ct.payment_status = $${paramIndex}`);
            queryParams.push(payment_status);
            paramIndex++;
        }

        if (token_number) {
            whereConditions.push(`ct.token_number = $${paramIndex}`);
            queryParams.push(token_number);
            paramIndex++;
        }

        if (merchant_name) {
            whereConditions.push(`m.merchant_name ILIKE $${paramIndex}`);
            queryParams.push(`%${merchant_name}%`);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`(
                ct.order_id ILIKE $${paramIndex} OR 
                ct.token_number ILIKE $${paramIndex} OR
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
            FROM cashier_transactions ct
            LEFT JOIN merchants m ON ct.token_number = m.token_number
            ${whereClause}
        `;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        // Get transactions details
        const dataQuery = `
            SELECT 
                ct.id,
                ct.order_id,
                ct.token_number,
                ct.gross_amount,
                ct.payment_status,
                ct.created_at,
                ct.updated_at,
                m.name as merchant_owner_name,
                m.merchant_name as merchant_name
            FROM cashier_transactions ct
            LEFT JOIN merchants m ON ct.token_number = m.token_number
            ${whereClause}
            ORDER BY ct.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.status(200).json({
            success: true,
            message: 'Transactions retrieved successfully',
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
        console.error('Get all transactions error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
