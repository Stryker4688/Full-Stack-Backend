// backend/src/index.ts - No changes to script imports
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import helmet from 'helmet';
import path from 'path';
import routes from './src/index';
import { connectRedis } from './src/config/redis';
import { requestLogger, errorLogger } from './src/middlewares/requestlogger';
import { logger } from './src/config/logger';
import { GoogleAuthService } from './src/services/googleAuthService';
import { EmailService } from './src/services/emailService';
import { createSuperAdmin, checkSuperAdmin } from './src/scripts/createSuperAdmin';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5001;

// Middleware - unchanged
app.use(helmet());
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'Patch'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//  Static file service for uploaded images
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Request logging
app.use(requestLogger);

// Routes - unchanged
app.use(routes);

// Error logging
app.use(errorLogger);

// Initialize services - unchanged  
GoogleAuthService.initialize();
EmailService.initialize();

// Connect to database and start server - unchanged in calling
mongoose.connect(process.env.DATABASE_URL!).then(() => {
    logger.info('Connected to MongoDB successfully');

    // Call exactly as per your base code
    createSuperAdmin();
    checkSuperAdmin();

    app.listen(PORT, () => {
        logger.info(`Server is running on port ${PORT}`);
        logger.info(`Environment: ${process.env.NODE_ENV}`);
        logger.info('Static file service initialized for uploads');
    });
}).catch((error) => {
    logger.error('Failed to connect to MongoDB', { error: error.message });
    process.exit(1);
});

// Redis connecting - unchanged
connectRedis().then(() => {
    logger.info('Redis initialization completed');
}).catch((error) => {
    logger.error('Redis initialization failed', { error: error.message });
});

// Add graceful shutdown - unchanged
process.on('SIGINT', async () => {
    logger.info('🛑 Received SIGINT, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGTERM', async () => {
    logger.info('🛑 Received SIGTERM, shutting down gracefully...');
    process.exit(0);
});