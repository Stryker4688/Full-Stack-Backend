// backend/src/controllers/testimonialController.ts - Optimized with cache utilities
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import Testimonial from '../../models/Testimonials';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import {
    clearTestimonialCache,
    generateKey,
    CACHE_TTL,
    cacheWithFallback
} from '../../utils/cacheUtils';

// Create new testimonial (public endpoint)
export const createTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const {
            name,
            email,
            message,
            rating = 5
        } = req.body;

        // Validate required fields
        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and message are required fields'
            });
        }

        // Create new testimonial
        const testimonial = new Testimonial({
            name,
            email,
            message,
            rating: parseInt(rating),
            isApproved: false,
            isActive: true
        });

        await testimonial.save();

        // Clear testimonial cache to reflect new submission
        await clearTestimonialCache();

        logger.info('New testimonial submitted successfully', {
            testimonialId: testimonial._id.toString(),
            name,
            email,
            rating
        });

        res.status(201).json({
            success: true,
            message: 'Your testimonial has been submitted successfully and will be displayed after admin approval',
            testimonial: {
                id: testimonial._id.toString(),
                name: testimonial.name,
                rating: testimonial.rating
            }
        });

    } catch (error: any) {
        LoggerService.errorLog('createTestimonial', error, {
            name: req.body.name,
            email: req.body.email
        });

        res.status(500).json({
            success: false,
            message: 'Error submitting testimonial',
            error: error.message
        });
    }
};

// Get approved testimonials for public display
export const getApprovedTestimonials = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Generate cache key based on query parameters
        const cacheKey = generateKey.testimonialList(
            Number(page),
            Number(limit),
            `${sortBy}:${sortOrder}`
        );

        // Use cache with fallback pattern
        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                const filter = {
                    isApproved: true,
                    isActive: true
                };

                const sort: any = {};
                sort[sortBy as string] = sortOrder === 'asc' ? 1 : -1;

                const testimonials = await Testimonial.find(filter)
                    .sort(sort)
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await Testimonial.countDocuments(filter);

                return {
                    success: true,
                    testimonials,
                    pagination: {
                        total,
                        page: Number(page),
                        limit: Number(limit),
                        totalPages: Math.ceil(total / Number(limit))
                    }
                };
            },
            CACHE_TTL.MEDIUM
        );

        res.json({
            ...responseData,
            fromCache: true // Indicate that data came from cache (handled internally in cacheWithFallback)
        });

    } catch (error: any) {
        LoggerService.errorLog('getApprovedTestimonials', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving testimonials',
            error: error.message
        });
    }
};

// Get all testimonials for admin management
export const getAllTestimonials = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            isApproved,
            isActive
        } = req.query;

        const cacheKey = `all_testimonials:${page}:${limit}:${isApproved}:${isActive}`;

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                const filter: any = {};

                if (isApproved !== undefined) {
                    filter.isApproved = isApproved === 'true';
                }

                if (isActive !== undefined) {
                    filter.isActive = isActive === 'true';
                }

                const testimonials = await Testimonial.find(filter)
                    .sort({ createdAt: -1 })
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await Testimonial.countDocuments(filter);

                // Get statistics for admin dashboard
                const stats = {
                    total: await Testimonial.countDocuments({}),
                    approved: await Testimonial.countDocuments({ isApproved: true, isActive: true }),
                    pending: await Testimonial.countDocuments({ isApproved: false, isActive: true })
                };

                return {
                    success: true,
                    testimonials,
                    stats,
                    pagination: {
                        total,
                        page: Number(page),
                        limit: Number(limit),
                        totalPages: Math.ceil(total / Number(limit))
                    }
                };
            },
            CACHE_TTL.SHORT
        );

        res.json(responseData);

    } catch (error: any) {
        LoggerService.errorLog('getAllTestimonials', error, {
            adminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving testimonials',
            error: error.message
        });
    }
};

// Approve testimonial (admin only)
export const approveTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const testimonial = await Testimonial.findByIdAndUpdate(
            id,
            {
                isApproved: true,
                isActive: true
            },
            { new: true }
        );

        if (!testimonial) {
            return res.status(404).json({
                success: false,
                message: 'Testimonial not found'
            });
        }

        // Clear testimonial cache to reflect changes
        await clearTestimonialCache();

        LoggerService.userLog(req.userId!, 'approve_testimonial', {
            testimonialId: id,
            userName: testimonial.name
        });

        logger.info('Testimonial approved by admin', {
            adminId: req.userId,
            testimonialId: id,
            userName: testimonial.name
        });

        res.json({
            success: true,
            message: 'Testimonial approved successfully and will be displayed on the testimonials page',
            testimonial
        });

    } catch (error: any) {
        LoggerService.errorLog('approveTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error approving testimonial',
            error: error.message
        });
    }
};

// Reject testimonial (admin only)
export const rejectTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const testimonial = await Testimonial.findByIdAndUpdate(
            id,
            {
                isApproved: false,
                isActive: false
            },
            { new: true }
        );

        if (!testimonial) {
            return res.status(404).json({
                success: false,
                message: 'Testimonial not found'
            });
        }

        // Clear testimonial cache
        await clearTestimonialCache();

        LoggerService.userLog(req.userId!, 'reject_testimonial', {
            testimonialId: id,
            userName: testimonial.name
        });

        res.json({
            success: true,
            message: 'Testimonial rejected and will not be displayed',
            testimonial
        });

    } catch (error: any) {
        LoggerService.errorLog('rejectTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error rejecting testimonial',
            error: error.message
        });
    }
};

// Delete testimonial (admin only)
export const deleteTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const testimonial = await Testimonial.findByIdAndDelete(id);

        if (!testimonial) {
            return res.status(404).json({
                success: false,
                message: 'Testimonial not found'
            });
        }

        // Clear testimonial cache
        await clearTestimonialCache();

        LoggerService.userLog(req.userId!, 'delete_testimonial', {
            testimonialId: id,
            userName: testimonial.name
        });

        res.json({
            success: true,
            message: 'Testimonial deleted successfully'
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error deleting testimonial',
            error: error.message
        });
    }
};

// Get testimonial statistics
export const getTestimonialStats = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = 'testimonial_stats';

        const stats = await cacheWithFallback(
            cacheKey,
            async () => {
                const stats = {
                    total: await Testimonial.countDocuments({}),
                    approved: await Testimonial.countDocuments({ isApproved: true, isActive: true }),
                    pending: await Testimonial.countDocuments({ isApproved: false, isActive: true }),
                    averageRating: 0
                };

                // Calculate average rating for approved testimonials
                const ratingStats = await Testimonial.aggregate([
                    {
                        $match: {
                            isApproved: true,
                            isActive: true
                        }
                    },
                    {
                        $group: {
                            _id: null,
                            averageRating: { $avg: "$rating" },
                            totalRatings: { $sum: 1 }
                        }
                    }
                ]);

                if (ratingStats.length > 0) {
                    stats.averageRating = Math.round(ratingStats[0].averageRating * 10) / 10;
                }

                return stats;
            },
            CACHE_TTL.SHORT
        );

        res.json({
            success: true,
            stats
        });

    } catch (error: any) {
        LoggerService.errorLog('getTestimonialStats', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving testimonial statistics',
            error: error.message
        });
    }
};