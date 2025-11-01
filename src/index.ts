import admin from './routes/admin/admin'
import auth from './routes/auth/auth'
import userManagement from './routes/users/userManagement'
import productRoutes from './routes/products/productRoutes'
import testimonialRoutes from './routes/Testimonials/testimonialRoutes' // 🆕 اضافه شد
import express from 'express'
import logger from './config/logger'

const router = express.Router()
router.get('/api/health', (req, res) => {
    logger.debug('Health check requested');
    res.json({ message: 'Server is running!', status: 'OK' });
});
router.use('/api/auth', auth)
router.use('/api', testimonialRoutes)
router.use('/api', productRoutes)
router.use('/api/admin', admin)
router.use('/api/management', userManagement)       



export default router