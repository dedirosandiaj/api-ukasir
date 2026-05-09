import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import { upload, deleteFile, getFileUrl, getFilenameFromUrl } from '../../utils/upload';

dotenv.config();

const router = Router();

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

// Input sanitization
const sanitizeString = (input: any, maxLength: number = 255): string | null => {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0 || trimmed.length > maxLength) return null;
    return trimmed.replace(/[<>\"']/g, '');
};

const generateSlug = (name: string): string => {
    return name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');
};

// HMAC Authentication Middleware
const verifyApiAuth = (req: Request, res: Response, next: Function): void => {
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

// Simple API Key Auth (for file uploads)
const verifyApiKey = (req: Request, res: Response, next: Function): void => {
    const API_KEY = process.env.API_KEY;
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
        res.status(401).json({ error: 'Missing API key' });
        return;
    }

    if (apiKey !== API_KEY) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
    }

    next();
};

// Upload Photo Endpoint
router.post('/products/upload-photo', verifyApiKey, upload.single('photo'), async (req: Request, res: Response) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const photoUrl = getFileUrl(req.file.filename);

        return res.status(200).json({
            success: true,
            message: 'Photo uploaded successfully',
            data: {
                filename: req.file.filename,
                url: photoUrl,
                size: req.file.size,
                mimetype: req.file.mimetype
            }
        });
    } catch (error: any) {
        console.error('Upload photo error:', error);
        
        if (req.file) {
            deleteFile(req.file.filename);
        }
        
        return res.status(500).json({
            error: 'Failed to upload photo',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get All Products
router.get('/products', verifyApiAuth, async (req: Request, res: Response) => {
    let client;
    try {
        client = await pool.connect();

        // Query parameters
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const status = req.query.status as string;
        const search = req.query.search as string;

        const offset = (page - 1) * limit;

        // Build query
        let whereConditions: string[] = [];
        let queryParams: any[] = [];
        let paramIndex = 1;

        if (status) {
            whereConditions.push(`status = $${paramIndex}`);
            queryParams.push(status);
            paramIndex++;
        }

        if (search) {
            whereConditions.push(`(name ILIKE $${paramIndex} OR slug ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
            queryParams.push(`%${search}%`);
            paramIndex++;
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

        // Get total count
        const countQuery = `SELECT COUNT(*) FROM product ${whereClause}`;
        const countResult = await client.query(countQuery, queryParams);
        const total = parseInt(countResult.rows[0].count);

        // Get products
        const dataQuery = `
            SELECT 
                id,
                name,
                slug,
                price,
                photo_url,
                description,
                status,
                created_at,
                updated_at
            FROM product 
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        queryParams.push(limit, offset);
        const dataResult = await client.query(dataQuery, queryParams);

        const totalPages = Math.ceil(total / limit);

        return res.status(200).json({
            success: true,
            message: 'Products retrieved successfully',
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
        console.error('Get products error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Get Product by Slug
router.get('/products/:slug', verifyApiAuth, async (req: Request, res: Response) => {
    const { slug } = req.params;
    let client;
    try {
        client = await pool.connect();

        const query = `
            SELECT * FROM product 
            WHERE slug = $1
            LIMIT 1
        `;
        const result = await client.query(query, [slug]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Product not found'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Product retrieved successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Get product error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Create Product
router.post('/products', verifyApiAuth, async (req: Request, res: Response) => {
    const { name, slug, price, photo_url, description, status } = req.body;
    let client;
    try {
        client = await pool.connect();

        // Validate required fields
        if (!name || price === undefined || price === null) {
            return res.status(400).json({ 
                error: 'Name and price are required' 
            });
        }

        // Sanitize inputs
        const sanitizedName = sanitizeString(name, 255);
        const sanitizedSlug = slug ? sanitizeString(slug, 255) : generateSlug(name);
        const sanitizedPhotoUrl = photo_url ? sanitizeString(photo_url, 500) : null;
        const sanitizedDescription = description ? sanitizeString(description, 5000) : null;
        const sanitizedStatus = status || 'active';

        if (!sanitizedName || !sanitizedSlug) {
            return res.status(400).json({ error: 'Invalid input data' });
        }

        // Validate price
        const productPrice = parseFloat(price);
        if (isNaN(productPrice) || productPrice < 0) {
            return res.status(400).json({ error: 'Invalid price. Must be a positive number' });
        }

        // Check if slug already exists
        const checkQuery = 'SELECT slug FROM product WHERE slug = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [sanitizedSlug]);

        if (checkResult.rows.length > 0) {
            return res.status(409).json({ 
                error: 'Product with this slug already exists' 
            });
        }

        // Insert product
        const insertQuery = `
            INSERT INTO product (name, slug, price, photo_url, description, status)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        `;

        const result = await client.query(insertQuery, [
            sanitizedName,
            sanitizedSlug,
            productPrice,
            sanitizedPhotoUrl,
            sanitizedDescription,
            sanitizedStatus
        ]);

        return res.status(201).json({
            success: true,
            message: 'Product created successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Create product error:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                error: 'Product name or slug already exists'
            });
        }
        
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Update Product
router.put('/products/:slug', verifyApiAuth, async (req: Request, res: Response) => {
    const { slug } = req.params;
    const { name, price, photo_url, description, status } = req.body;
    let client;
    try {
        client = await pool.connect();

        // Check if product exists
        const checkQuery = 'SELECT * FROM product WHERE slug = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [slug]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const existingProduct = checkResult.rows[0];

        // Sanitize inputs (use existing values if not provided)
        const sanitizedName = name ? sanitizeString(name, 255) : existingProduct.name;
        const sanitizedSlug = name ? generateSlug(name) : slug;
        const sanitizedPhotoUrl = photo_url !== undefined ? (photo_url ? sanitizeString(photo_url, 500) : null) : existingProduct.photo_url;
        const sanitizedDescription = description !== undefined ? (description ? sanitizeString(description, 5000) : null) : existingProduct.description;
        const sanitizedStatus = status || existingProduct.status;

        if (!sanitizedName) {
            return res.status(400).json({ error: 'Invalid input data' });
        }

        // Validate price if provided
        let productPrice = existingProduct.price;
        if (price !== undefined && price !== null) {
            productPrice = parseFloat(price);
            if (isNaN(productPrice) || productPrice < 0) {
                return res.status(400).json({ error: 'Invalid price. Must be a positive number' });
            }
        }

        // Update product
        const updateQuery = `
            UPDATE product SET
                name = $1,
                slug = $2,
                price = $3,
                photo_url = $4,
                description = $5,
                status = $6,
                updated_at = NOW()
            WHERE slug = $7
            RETURNING *
        `;

        const result = await client.query(updateQuery, [
            sanitizedName,
            sanitizedSlug,
            productPrice,
            sanitizedPhotoUrl,
            sanitizedDescription,
            sanitizedStatus,
            slug
        ]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        return res.status(200).json({
            success: true,
            message: 'Product updated successfully',
            data: result.rows[0]
        });

    } catch (error: any) {
        console.error('Update product error:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                error: 'Product name or slug already exists'
            });
        }
        
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

// Delete Product
router.delete('/products/:slug', verifyApiAuth, async (req: Request, res: Response) => {
    const { slug } = req.params;
    let client;
    try {
        client = await pool.connect();

        // Check if product exists
        const checkQuery = 'SELECT * FROM product WHERE slug = $1 LIMIT 1';
        const checkResult = await client.query(checkQuery, [slug]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Delete product
        const deleteQuery = 'DELETE FROM product WHERE slug = $1 RETURNING *';
        const result = await client.query(deleteQuery, [slug]);

        return res.status(200).json({
            success: true,
            message: 'Product deleted successfully',
            data: {
                id: result.rows[0].id,
                name: result.rows[0].name,
                slug: result.rows[0].slug,
                deleted_at: new Date().toISOString()
            }
        });

    } catch (error: any) {
        console.error('Delete product error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) client.release();
    }
});

export default router;
