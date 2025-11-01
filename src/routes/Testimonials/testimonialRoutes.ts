// backend/src/routes/Testimonials/testimonialRoutes.ts
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireAdmin } from '../../middlewares/adminAuth';
import {
    createTestimonial,
    getApprovedTestimonials,
    getAllTestimonials,
    approveTestimonial,
    rejectTestimonial,
    deleteTestimonial,
    getTestimonialStats
} from './testimonialController';

const router = express.Router();

// ✅ Routes عمومی برای کاربران - بدون احراز هویت
router.get('/testimonials/approved', getApprovedTestimonials);
router.post('/testimonials', createTestimonial);
router.get('/testimonials/stats', getTestimonialStats);

// ✅ Routes مدیریتی برای ادمین - با احراز هویت
router.get('/admin/testimonials', authenticateToken, requireAdmin, getAllTestimonials);
router.patch('/admin/testimonials/:id/approve', authenticateToken, requireAdmin, approveTestimonial);
router.patch('/admin/testimonials/:id/reject', authenticateToken, requireAdmin, rejectTestimonial);
router.delete('/admin/testimonials/:id', authenticateToken, requireAdmin, deleteTestimonial);

export default router;