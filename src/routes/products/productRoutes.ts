// backend/src/routes/productRoutes.ts - به‌روزرسانی شده
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireAdmin } from '../../middlewares/adminAuth';
import upload from '../../config/multerConfig';
import {
    createProduct,
    updateProduct,
    deleteProduct,
    getProductById,
    deleteProductImage,
    getAdminProducts,
    getFeaturedProducts,    // برای صفحه home - بخش offer
    getMenuProducts,        // برای صفحه home - بخش menu
    searchProducts,         // برای جستجو در menu
    getPopularProducts      // برای محصولات پرطرفدار در menu
} from './productController';
import { productValidation } from '../../middlewares/productValidation';

const router = express.Router();

// 🆕 Routes برای صفحات فرانت‌اند - بدون نیاز به احراز هویت
router.get('/home/offer', getFeaturedProducts);     // صفحه home - بخش offer
router.get('/home/menu', getMenuProducts);          // صفحه home - بخش menu
router.get('/home/menu/search', searchProducts);    // جستجو در منو
router.get('/home/menu/popular', getPopularProducts); // محصولات پرطرفدار در منو

// Routes عمومی (برای موارد خاص)
router.get('/products/:id', getProductById); // فقط برای مشاهده جزئیات محصول

// Routes مدیریتی (نیاز به ادمین)
router.use(authenticateToken);
router.use(requireAdmin);

// مدیریت محصولات - فقط برای ادمین
router.post('/admin/products', upload.array('images', 5), productValidation, createProduct);
router.put('/admin/products/:id', upload.array('images', 5), productValidation, updateProduct);
router.delete('/admin/products/:id', deleteProduct);
router.delete('/admin/products/:id/images/:imageUrl', deleteProductImage);
router.get('/admin/products', getAdminProducts);

export default router;