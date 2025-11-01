// backend/src/config/multerConfig.ts
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request } from 'express';
import { logger } from './logger';

// ایجاد پوشه uploads اگر وجود ندارد
const uploadsDir = path.join(__dirname, '../../uploads/products');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// پیکربندی storage
const storage = multer.diskStorage({
    destination: (req: Request, file: Express.Multer.File, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req: Request, file: Express.Multer.File, cb) => {
        // ایجاد نام فایل منحصر به فرد
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'product-' + uniqueSuffix + ext);
    }
});

// فیلتر فایل‌ها برای فقط تصاویر
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
        cb(new Error('فقط فایل‌های تصویری مجاز هستند (JPEG, PNG, WebP, GIF)'));
    }
};

// پیکربندی multer
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
        files: 5 // حداکثر 5 فایل
    }
});

// تابع برای حذف فایل
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

// تابع برای گرفتن URL فایل
export const getFileUrl = (filename: string): string => {
    return `/uploads/products/${filename}`;
};

export default upload;