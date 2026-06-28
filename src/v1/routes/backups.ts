import { Router, Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import AWS from 'aws-sdk';

const router = Router();

// ponytail: minimum db connection (YAGNI centralizing if it's just this simple)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// ponytail: direct aws-sdk S3 config without unnecessary abstraction
const s3 = new AWS.S3({
    endpoint: process.env.S3_ENDPOINT,
    accessKeyId: process.env.S3_ACCESS_KEY,
    secretAccessKey: process.env.S3_SECRET_KEY,
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
});

const BUCKET = process.env.S3_UKASIR_BUCKET || 'ukasir';

// ponytail: inline simple middleware for Bearer token
const verifyBearerToken = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized' });
    
    const token = authHeader.split(' ')[1];
    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT token_number FROM merchants WHERE token_number = $1 AND status_active = true', [token]);
        if (result.rowCount === 0) return res.status(401).json({ success: false, message: 'Invalid or inactive token' });
        
        (req as any).merchant_token = token;
        next();
    } catch (e) {
        return res.status(500).json({ success: false, message: 'DB Error' });
    } finally {
        if (client) client.release();
    }
};

// GET /api/v1/backups
router.get('/backups', verifyBearerToken, async (req: Request, res: Response): Promise<any> => {
    const token = (req as any).merchant_token;
    const prefix = `${token}/`; 
    
    try {
        const data = await s3.listObjectsV2({ Bucket: BUCKET, Prefix: prefix }).promise();
        const files = (data.Contents || [])
            .filter(obj => obj.Key?.endsWith('.sql') || obj.Key?.endsWith('.db'))
            .map(obj => {
                const fileName = obj.Key!.split('/').pop();
                const lastModified = obj.LastModified ? new Date(obj.LastModified) : new Date();
                
                // ponytail: simple size formatting inline
                const sizeBytes = obj.Size || 0;
                const size = sizeBytes > 1024 * 1024 
                    ? (sizeBytes / (1024 * 1024)).toFixed(1) + 'MB' 
                    : (sizeBytes / 1024).toFixed(1) + 'KB';

                return {
                    file_name: fileName,
                    date: lastModified.toISOString().split('T')[0],
                    time: lastModified.toTimeString().split(' ')[0],
                    size
                };
            });
        return res.json({ success: true, data: files });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'S3 Error' });
    }
});

// POST /api/v1/backups/upload-url
router.post('/backups/upload-url', verifyBearerToken, async (req: Request, res: Response): Promise<any> => {
    const token = (req as any).merchant_token;
    const { file_name, content_type } = req.body;
    
    if (!file_name) return res.status(400).json({ success: false, message: 'file_name required' });
    
    try {
        const url = await s3.getSignedUrlPromise('putObject', {
            Bucket: BUCKET,
            Key: `${token}/${file_name}`,
            ContentType: content_type || 'application/octet-stream',
            Expires: 600 // 10 minutes
        });
        return res.json({ success: true, data: { upload_url: url } });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'S3 Error' });
    }
});

// POST /api/v1/backups/download-url
router.post('/backups/download-url', verifyBearerToken, async (req: Request, res: Response): Promise<any> => {
    const token = (req as any).merchant_token;
    const { file_name } = req.body;
    
    if (!file_name) return res.status(400).json({ success: false, message: 'file_name required' });
    
    try {
        const url = await s3.getSignedUrlPromise('getObject', {
            Bucket: BUCKET,
            Key: `${token}/${file_name}`,
            Expires: 600
        });
        return res.json({ success: true, data: { download_url: url } });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'S3 Error' });
    }
});

// DELETE /api/v1/backups/:file_name
router.delete('/backups/:file_name', verifyBearerToken, async (req: Request, res: Response): Promise<any> => {
    const token = (req as any).merchant_token;
    const { file_name } = req.params;
    
    try {
        await s3.deleteObject({ Bucket: BUCKET, Key: `${token}/${file_name}` }).promise();
        return res.json({ success: true, message: 'File backup berhasil dihapus.' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'S3 Error' });
    }
});

export default router;
