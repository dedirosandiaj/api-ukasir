import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Ensure upload directory exists
const uploadDir = path.join(process.cwd(), 'uploads', 'products');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        cb(null, `product-${uniqueSuffix}-${name}${ext}`);
    }
});

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

// Helper to delete file
export const deleteFile = (filename: string): void => {
    if (!filename) return;
    
    const filepath = path.join(process.cwd(), 'uploads', 'products', filename);
    if (fs.existsSync(filepath)) {
        fs.unlinkSync(filepath);
    }
};

// Helper to get file URL from filename
export const getFileUrl = (filename: string): string => {
    if (!filename) return '';
    
    // For production, this should be your CDN or server URL
    const baseUrl = process.env.UPLOAD_BASE_URL || 'https://api.ukasir.id';
    return `${baseUrl}/uploads/products/${filename}`;
};

// Helper to get filename from URL
export const getFilenameFromUrl = (url: string): string => {
    if (!url) return '';
    return url.split('/').pop() || '';
};
