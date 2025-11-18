// backend/src/config/multerConfig.ts
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request } from 'express';
import { logger } from './logger';

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, '../../uploads/products');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
    destination: (req: Request, file: Express.Multer.File, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req: Request, file: Express.Multer.File, cb) => {
        // Create unique filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'product-' + uniqueSuffix + ext);
    }
});

// File filter for images only
const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedMimes = [
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/webp',
        'image/gif'
    ];

    if (allowedMimes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed (JPEG, PNG, WebP, GIF)'));
    }
};

// Configure multer
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
        files: 5 // Maximum 5 files
    }
});

// Function to delete file from server
export const deleteFile = (filename: string): Promise<void> => {
    return new Promise((resolve, reject) => {
        const filePath = path.join(uploadsDir, filename);
        fs.unlink(filePath, (err) => {
            if (err) {
                logger.error('Error deleting file:', { filename, error: err.message });
                reject(err);
            } else {
                logger.debug('File deleted successfully:', { filename });
                resolve();
            }
        });
    });
};

// Function to get file URL for client access
export const getFileUrl = (filename: string): string => {
    return `/uploads/products/${filename}`;
};

export default upload;