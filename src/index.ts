// backend/src/index.ts - اصلاح استفاده از نوع
import admin from './routes/admin/admin'
import auth from './routes/auth/auth'
import userManagement from './routes/users/userManagement'
import productRoutes from './routes/products/productRoutes'
import testimonialRoutes from './routes/Testimonials/testimonialRoutes'
import express from 'express'
import logger from './config/logger'
import { authenticateToken } from './middlewares/auth'
import { requireAdmin, requireSuperAdmin } from './middlewares/adminAuth'
import {
    getCacheStats,
    checkCacheHealth,
    clearProductCache,
    clearTestimonialCache,
    clearUserCache,
    clearAdminCache,
    cacheDeletePattern
} from './utils/cacheUtils'

const router = express.Router()

// Health check with cache status
router.get('/api/health', async (req, res) => {
    try {
        const cacheHealth = await checkCacheHealth();

        res.json({
            message: 'Server is running!',
            status: 'OK',
            timestamp: new Date().toISOString(),
            cache: cacheHealth.healthy ? 'Connected' : 'Disconnected',
            cacheLatency: cacheHealth.latency ? `${cacheHealth.latency}ms` : 'N/A'
        });
    } catch (error) {
        res.status(500).json({
            message: 'Server error',
            status: 'ERROR'
        });
    }
});

// Cache management routes (Admin only)
router.get('/api/admin/cache/stats',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            const stats = await getCacheStats();
            res.json({
                success: true,
                ...stats
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to get cache stats'
            });
        }
    }
);

router.get('/api/admin/cache/health',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            const health = await checkCacheHealth();
            res.json({
                success: true,
                healthy: health.healthy,
                latency: health.latency
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to check cache health'
            });
        }
    }
);

// بقیه routeها بدون تغییر...
router.post('/api/admin/cache/clear/products',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            await clearProductCache();
            res.json({
                success: true,
                message: 'Product cache cleared successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to clear product cache'
            });
        }
    }
);

router.post('/api/admin/cache/clear/testimonials',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            await clearTestimonialCache();
            res.json({
                success: true,
                message: 'Testimonial cache cleared successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to clear testimonial cache'
            });
        }
    }
);

router.post('/api/admin/cache/clear/users',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            await cacheDeletePattern('users:*');
            res.json({
                success: true,
                message: 'User cache cleared successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to clear user cache'
            });
        }
    }
);

router.post('/api/admin/cache/clear/all',
    authenticateToken,
    requireSuperAdmin,
    async (req, res) => {
        try {
            await clearProductCache();
            await clearTestimonialCache();
            await clearAdminCache();
            await cacheDeletePattern('users:*');
            await cacheDeletePattern('rate_limit:*');

            res.json({
                success: true,
                message: 'All caches cleared successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to clear all caches'
            });
        }
    }
);

// User-specific cache clearance
router.post('/api/admin/cache/clear/user/:userId',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            const { userId } = req.params;
            await clearUserCache(userId);

            res.json({
                success: true,
                message: `User cache for ${userId} cleared successfully`
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Failed to clear user cache'
            });
        }
    }
);

// Main routes
router.use('/api/auth', auth)
router.use('/api/admin', admin)
router.use('/api/management', userManagement)
router.use('/api', testimonialRoutes)
router.use('/api', productRoutes)

export default router