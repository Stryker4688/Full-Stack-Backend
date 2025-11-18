// backend/src/routes/testimonialRoutes.ts
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireAdmin } from '../../middlewares/adminAuth';
import { testimonialValidation } from '../../middlewares/testimonialValidation';
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

// ✅ Public routes for users - no authentication required
router.get('/testimonials/approved', getApprovedTestimonials);
router.post('/testimonials', testimonialValidation, createTestimonial);
router.get('/testimonials/stats', getTestimonialStats);

// ✅ Administrative routes for admin - with authentication
router.get('/admin/testimonials', authenticateToken, requireAdmin, getAllTestimonials);
router.patch('/admin/testimonials/:id/approve', authenticateToken, requireAdmin, approveTestimonial);
router.patch('/admin/testimonials/:id/reject', authenticateToken, requireAdmin, rejectTestimonial);
router.delete('/admin/testimonials/:id', authenticateToken, requireAdmin, deleteTestimonial);

export default router;