import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import { upload, uploadQrisToS3, deleteQrisFromS3 } from '../../utils/upload';

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

// Multer upload fields config for POST/PUT files
const qrisUploadFields = upload.fields([
    { name: 'attachment_account_book', maxCount: 1 },
    { name: 'attachment_identity_card', maxCount: 1 }
]);

// 1. Submit QRIS Activation Request (Authenticated clients)
router.post('/qris-activations', verifyApiAuth, qrisUploadFields, async (req: Request, res: Response) => {
    const { token_number, account_name, account_name_owner, account_number_owner, agree_terms } = req.body;
    let client;

    try {
        // Validation: agree_terms is required and must be true/"true"
        const isAgreed = agree_terms === true || agree_terms === 'true';
        if (!isAgreed) {
            return res.status(400).json({ error: 'Syarat & ketentuan wajib disetujui' });
        }

        // Validate required fields
        if (!token_number || !account_name || !account_name_owner || !account_number_owner) {
            return res.status(400).json({ error: 'token_number, account_name, account_name_owner, and account_number_owner are required' });
        }

        if (!isValidTokenFormat(token_number)) {
            return res.status(400).json({ error: 'Invalid token format. Expected: XXXX-XXXX-XXXX-XXXX' });
        }

        const sanitizedToken = sanitizeString(token_number, 255);
        const sanitizedAccountName = sanitizeString(account_name, 255);
        const sanitizedOwnerName = sanitizeString(account_name_owner, 255);
        const sanitizedOwnerNumber = sanitizeString(account_number_owner, 100);

        if (!sanitizedToken || !sanitizedAccountName || !sanitizedOwnerName || !sanitizedOwnerNumber) {
            return res.status(400).json({ error: 'Invalid input data' });
        }

        // Validate uploaded files
        const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
        const accountBookFile = files?.['attachment_account_book']?.[0];
        const identityCardFile = files?.['attachment_identity_card']?.[0];

        if (!accountBookFile || !identityCardFile) {
            return res.status(400).json({ error: 'Both attachment_account_book and attachment_identity_card files are required' });
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

        // Upload files to S3
        const attachmentAccountBookUrl = await uploadQrisToS3(accountBookFile);
        const attachmentIdentityCardUrl = await uploadQrisToS3(identityCardFile);

        // Insert request details
        const query = `
            INSERT INTO qris_activations (
                id, token_number, account_name, account_name_owner, account_number_owner, 
                attachment_account_book, attachment_identity_card, agree_terms, status
            )
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, 'pending')
            RETURNING *
        `;

        const result = await client.query(query, [
            sanitizedToken,
            sanitizedAccountName,
            sanitizedOwnerName,
            sanitizedOwnerNumber,
            attachmentAccountBookUrl,
            attachmentIdentityCardUrl,
            true
        ]);

        return res.status(201).json({
            success: true,
            message: 'QRIS Activation request submitted successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Create QRIS activation error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 2. Get All QRIS Activation Requests (Superadmin only)
router.get('/qris-activations', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const status = req.query.status as string; // pending, approved, rejected
        const search = req.query.search as string;

        const offset = (page - 1) * limit;

        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (status) {
            whereConditions.push(`status = $${paramIndex}`);
            queryParams.push(status);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`(
                token_number ILIKE $${paramIndex} OR 
                account_name ILIKE $${paramIndex} OR 
                account_name_owner ILIKE $${paramIndex} OR 
                account_number_owner ILIKE $${paramIndex}
            )`);
            queryParams.push(`%${search}%`);
            paramIndex++;
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

        // Get total count
        const countQuery = `SELECT COUNT(*) FROM qris_activations ${whereClause}`;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        // Get details
        const dataQuery = `
            SELECT * FROM qris_activations
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.status(200).json({
            success: true,
            message: 'QRIS Activation requests retrieved successfully',
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
        console.error('Get QRIS activations error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 3. Get QRIS Activation Request Details (Superadmin only)
router.get('/qris-activations/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();
        const query = 'SELECT * FROM qris_activations WHERE id = $1::uuid LIMIT 1';
        const result = await client.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'QRIS Activation request not found' });
        }

        return res.status(200).json({
            success: true,
            data: result.rows[0]
        });
    } catch (error: any) {
        console.error('Get QRIS activation detail error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 4. Update QRIS Activation Request Status (Superadmin only)
router.put('/qris-activations/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { status } = req.body;
    let client;

    try {
        if (!status) {
            return res.status(400).json({ error: 'Status is required' });
        }

        if (status !== 'pending' && status !== 'approved' && status !== 'rejected') {
            return res.status(400).json({ error: 'Invalid status. Allowed values: pending, approved, rejected' });
        }

        client = await pool.connect();

        // Check if exists
        const checkQuery = 'SELECT * FROM qris_activations WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'QRIS Activation request not found' });
        }

        // Update status
        const updateQuery = `
            UPDATE qris_activations
            SET status = $1, updated_at = NOW()
            WHERE id = $2::uuid
            RETURNING *
        `;
        const result = await client.query(updateQuery, [status, id]);

        return res.status(200).json({
            success: true,
            message: 'QRIS Activation status updated successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update QRIS activation error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// 5. Delete QRIS Activation Request (Superadmin only)
router.delete('/qris-activations/:id', verifyApiAuth, verifySuperAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;
    let client;
    try {
        client = await pool.connect();

        // Check if exists and retrieve S3 URLs
        const checkQuery = 'SELECT id, attachment_account_book, attachment_identity_card FROM qris_activations WHERE id = $1::uuid LIMIT 1';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'QRIS Activation request not found' });
        }

        const dataToDelete = checkResult.rows[0];

        // Delete files from MinIO
        if (dataToDelete.attachment_account_book) {
            await deleteQrisFromS3(dataToDelete.attachment_account_book);
        }
        if (dataToDelete.attachment_identity_card) {
            await deleteQrisFromS3(dataToDelete.attachment_identity_card);
        }

        // Delete from database
        const deleteQuery = 'DELETE FROM qris_activations WHERE id = $1::uuid RETURNING *';
        const result = await client.query(deleteQuery, [id]);

        return res.status(200).json({
            success: true,
            message: 'QRIS Activation request deleted successfully',
            data: {
                id: result.rows[0].id,
                deleted_at: new Date().toISOString()
            }
        });

    } catch (error: any) {
        console.error('Delete QRIS activation error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
