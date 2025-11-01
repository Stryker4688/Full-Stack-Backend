// backend/src/index.ts
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import helmet from 'helmet';
import path from 'path'; // 🆕 اضافه شد
import routes from './src/index'
import { connectRedis } from './src/config/redis';
import { requestLogger, errorLogger } from './src/middlewares/requestlogger';
import { logger } from './src/config/logger';
import { GoogleAuthService } from './src/services/googleAuthService'
import { EmailService } from './src/services/emailService';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(helmet());
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'Patch'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🆕 سرویس فایل‌های استاتیک برای عکس‌های آپلود شده
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// لاگینگ درخواست‌ها
app.use(requestLogger);
// Routes
app.use(routes);
// لاگینگ خطاها
app.use(errorLogger);
//initialize services  
GoogleAuthService.initialize()
EmailService.initialize()
// Connect to database and start server
mongoose.connect(process.env.DATABASE_URL!).then(() => {
    logger.info('Connected to MongoDB successfully');

    app.listen(PORT, () => {
        logger.info(`Server is running on port ${PORT}`);
        logger.info(`Environment: ${process.env.NODE_ENV}`);

        // 🆕 لاگ برای اطمینان از فعال بودن سرویس آپلود
        logger.info('Static file service initialized for uploads');
    });
}).catch((error) => {
    logger.error('Failed to connect to MongoDB', { error: error.message });
    process.exit(1);
});
//redis connecting
connectRedis().then(() => {
    logger.info('Redis initialization completed');
}).catch((error) => {
    logger.error('Redis initialization failed', { error: error.message });
});
// اضافه کردن graceful shutdown socket.io
process.on('SIGINT', async () => {
    logger.info('🛑 Received SIGINT, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGTERM', async (err) => {
    logger.info('🛑 Received SIGTERM, shutting down gracefully...');
    process.exit(0);
});