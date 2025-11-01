// backend/src/controllers/testimonialController.ts - بهینه‌سازی شده با Redis
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import Testimonial from '../../models/Testimonials';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { redisClient } from '../../config/redis';

// کلیدهای کش
const CACHE_KEYS = {
    APPROVED_TESTIMONIALS: 'approved_testimonials',
    ALL_TESTIMONIALS: 'all_testimonials',
    TESTIMONIAL_STATS: 'testimonial_stats',
    TESTIMONIAL_DETAIL: 'testimonial_detail'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
    SHORT: 300,    // 5 دقیقه
    MEDIUM: 1800,  // 30 دقیقه
    LONG: 3600     // 1 ساعت
};

// توابع کمکی کش
const cacheGet = async (key: string): Promise<any> => {
    try {
        const cached = await redisClient.get(key);
        return cached ? JSON.parse(cached) : null;
    } catch (error) {
        logger.error('Cache get error', { key, error });
        return null;
    }
};

const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.error('Cache set error', { key, error });
    }
};

const invalidateTestimonialCache = async (): Promise<void> => {
    try {
        const keys = await redisClient.keys(`${CACHE_KEYS.APPROVED_TESTIMONIALS}:*`);
        const allKeys = await redisClient.keys(`${CACHE_KEYS.ALL_TESTIMONIALS}:*`);
        const statsKeys = await redisClient.keys(`${CACHE_KEYS.TESTIMONIAL_STATS}:*`);

        const allCacheKeys = [...keys, ...allKeys, ...statsKeys];

        if (allCacheKeys.length > 0) {
            await redisClient.del(allCacheKeys);
            logger.debug('Testimonial cache invalidated', { keysCount: allCacheKeys.length });
        }
    } catch (error) {
        logger.error('Testimonial cache invalidation error', { error });
    }
};

// ایجاد نظر جدید توسط کاربر
export const createTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const {
            name,
            email,
            message,
            rating = 5
        } = req.body;

        // ایجاد نظر جدید
        const testimonial = new Testimonial({
            name,
            email,
            message,
            rating: parseInt(rating),
            isApproved: false,
            isActive: true
        });

        await testimonial.save();

        // 🔥 حذف کش مرتبط
        await invalidateTestimonialCache();

        logger.info('New testimonial submitted', {
            testimonialId: testimonial._id.toString(),
            name,
            email,
            rating
        });

        res.status(201).json({
            success: true,
            message: 'نظر شما با موفقیت ثبت شد و پس از تایید مدیریت نمایش داده خواهد شد',
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
            message: 'خطا در ثبت نظر',
            error: error.message
        });
    }
};

// دریافت نظرات تایید شده برای نمایش در صفحه Testimonials
export const getApprovedTestimonials = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const cacheKey = `${CACHE_KEYS.APPROVED_TESTIMONIALS}:${page}:${limit}:${sortBy}:${sortOrder}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            logger.debug('Serving approved testimonials from cache', { cacheKey });
            return res.json({
                ...cached,
                fromCache: true
            });
        }

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

        const responseData = {
            success: true,
            testimonials,
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            }
        };

        // ذخیره در کش
        await cacheSet(cacheKey, responseData, CACHE_TTL.MEDIUM);

        res.json({
            ...responseData,
            fromCache: false
        });

    } catch (error: any) {
        LoggerService.errorLog('getApprovedTestimonials', error);
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت نظرات',
            error: error.message
        });
    }
};

// دریافت تمام نظرات برای ادمین (تایید شده و نشده)
export const getAllTestimonials = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            isApproved,
            isActive
        } = req.query;

        const cacheKey = `${CACHE_KEYS.ALL_TESTIMONIALS}:${page}:${limit}:${isApproved}:${isActive}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            logger.debug('Serving all testimonials from cache', { cacheKey });
            return res.json({
                ...cached,
                fromCache: true
            });
        }

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

        // آمار برای ادمین
        const stats = {
            total: await Testimonial.countDocuments({}),
            approved: await Testimonial.countDocuments({ isApproved: true, isActive: true }),
            pending: await Testimonial.countDocuments({ isApproved: false, isActive: true })
        };

        const responseData = {
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

        // ذخیره در کش
        await cacheSet(cacheKey, responseData, CACHE_TTL.SHORT);

        res.json({
            ...responseData,
            fromCache: false
        });

    } catch (error: any) {
        LoggerService.errorLog('getAllTestimonials', error, {
            adminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت نظرات',
            error: error.message
        });
    }
};

// تایید نظر توسط ادمین
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
                message: 'نظر یافت نشد'
            });
        }

        // 🔥 حذف کش مرتبط
        await invalidateTestimonialCache();

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
            message: 'نظر با موفقیت تایید شد و در صفحه نظرات نمایش داده خواهد شد',
            testimonial
        });

    } catch (error: any) {
        LoggerService.errorLog('approveTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'خطا در تایید نظر',
            error: error.message
        });
    }
};

// رد نظر توسط ادمین
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
                message: 'نظر یافت نشد'
            });
        }

        // 🔥 حذف کش مرتبط
        await invalidateTestimonialCache();

        LoggerService.userLog(req.userId!, 'reject_testimonial', {
            testimonialId: id,
            userName: testimonial.name
        });

        res.json({
            success: true,
            message: 'نظر رد شد و نمایش داده نخواهد شد',
            testimonial
        });

    } catch (error: any) {
        LoggerService.errorLog('rejectTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'خطا در رد نظر',
            error: error.message
        });
    }
};

// حذف نظر توسط ادمین
export const deleteTestimonial = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const testimonial = await Testimonial.findByIdAndDelete(id);

        if (!testimonial) {
            return res.status(404).json({
                success: false,
                message: 'نظر یافت نشد'
            });
        }

        // 🔥 حذف کش مرتبط
        await invalidateTestimonialCache();

        LoggerService.userLog(req.userId!, 'delete_testimonial', {
            testimonialId: id,
            userName: testimonial.name
        });

        res.json({
            success: true,
            message: 'نظر با موفقیت حذف شد'
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteTestimonial', error, {
            adminId: req.userId,
            testimonialId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'خطا در حذف نظر',
            error: error.message
        });
    }
};

// دریافت آمار نظرات
export const getTestimonialStats = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = CACHE_KEYS.TESTIMONIAL_STATS;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            return res.json({
                success: true,
                stats: cached,
                fromCache: true
            });
        }

        const stats = {
            total: await Testimonial.countDocuments({}),
            approved: await Testimonial.countDocuments({ isApproved: true, isActive: true }),
            pending: await Testimonial.countDocuments({ isApproved: false, isActive: true }),
            averageRating: 0
        };

        // محاسبه میانگین امتیاز نظرات تایید شده
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

        // ذخیره در کش
        await cacheSet(cacheKey, stats, CACHE_TTL.SHORT);

        res.json({
            success: true,
            stats,
            fromCache: false
        });

    } catch (error: any) {
        LoggerService.errorLog('getTestimonialStats', error);
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت آمار نظرات',
            error: error.message
        });
    }
};