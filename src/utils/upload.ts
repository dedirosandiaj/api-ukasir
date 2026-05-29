import multer from 'multer';
import path from 'path';
import fs from 'fs';
import AWS from 'aws-sdk';
import dotenv from 'dotenv';

dotenv.config();

// MinIO S3 Configuration
const s3 = new AWS.S3({
    endpoint: process.env.S3_ENDPOINT || 'https://s3.ucentric.id',
    accessKeyId: process.env.S3_ACCESS_KEY || 'oXIbZJQ9bJQHnvu0',
    secretAccessKey: process.env.S3_SECRET_KEY || 'r204fGZT9SEqqNzAYOSCM0GriNPrjaTh',
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
});

const S3_BUCKET = process.env.S3_BUCKET || 'products';
const S3_BASE_URL = process.env.S3_BASE_URL || 'https://s3.ucentric.id';

// Multer memory storage (for S3 upload)
const storage = multer.memoryStorage();

// File filter - only images
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
    }
};

// Multer config
export const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB max
    },
    fileFilter: fileFilter
});

// Upload file to S3
export const uploadToS3 = async (file: Express.Multer.File): Promise<string> => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    const filename = `product-${uniqueSuffix}-${name}${ext}`;

    const params = {
        Bucket: S3_BUCKET,
        Key: filename,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read'
    };

    const result = await s3.upload(params).promise();
    return result.Location;
};

// Delete file from S3
export const deleteFromS3 = async (fileUrl: string): Promise<void> => {
    if (!fileUrl) return;
    
    // Extract filename from URL
    const filename = getFilenameFromUrl(fileUrl);
    if (!filename) return;

    const params = {
        Bucket: S3_BUCKET,
        Key: filename
    };

    try {
        await s3.deleteObject(params).promise();
    } catch (error) {
        console.error('Error deleting file from S3:', error);
    }
};

// Helper to get filename from URL
export const getFilenameFromUrl = (url: string): string => {
    if (!url) return '';
    return url.split('/').pop() || '';
};
