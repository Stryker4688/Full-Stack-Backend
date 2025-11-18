// backend/src/routes/productRoutes.ts
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireAdmin } from '../../middlewares/adminAuth';
import upload from '../../config/multerConfig';
import { productValidation } from '../../middlewares/productValidation';
import {
    createProduct,
    updateProduct,
    deleteProduct,
    getProductById,
    deleteProductImage,
    getAdminProducts,
    getFeaturedProducts,
    getMenuProducts,
    searchProducts,
    getPopularProducts
} from './productController';

const router = express.Router();

// 🆕 Frontend Routes - No authentication required
router.get('/home/offer', getFeaturedProducts);     // Home page - offer section
router.get('/home/menu', getMenuProducts);          // Home page - menu section
router.get('/home/menu/search', searchProducts);    // Search in menu
router.get('/home/menu/popular', getPopularProducts); // Popular products in menu

// General Routes (for specific cases)
router.get('/products/:id', getProductById); // Only for viewing product details

// Administrative Routes (Admin required)
router.use(authenticateToken);
router.use(requireAdmin);

// Product Management - Admin only
router.post('/admin/products', upload.array('images', 5), productValidation, createProduct);
router.put('/admin/products/:id', upload.array('images', 5), productValidation, updateProduct);
router.delete('/admin/products/:id', deleteProduct);
router.delete('/admin/products/:id/images/:imageUrl', deleteProductImage);
router.get('/admin/products', getAdminProducts);

export default router;