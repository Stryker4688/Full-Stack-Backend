// backend/src/controllers/productController.ts - Optimized with Redis
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import Product from '../../models/product';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { deleteFile, getFileUrl } from '../../config/multerConfig';
import {
    clearProductCache,
    generateKey,
    CACHE_TTL,
    cacheWithFallback
} from '../../utils/cacheUtils';

// Cache key constants for different product data types
const CACHE_KEYS = {
    FEATURED: 'featured_products',
    MENU: 'menu_products',
    POPULAR: 'popular_products',
    PRODUCT_DETAIL: 'product_detail',
    SEARCH: 'product_search',
    CATEGORIES: 'product_categories'
};

// Get featured products for home page offers
export const getFeaturedProducts = async (req: AuthRequest, res: Response) => {
    try {
        const { limit = 8 } = req.query;
        const cacheKey = generateKey.featuredProducts(Number(limit));

        const products = await cacheWithFallback(
            cacheKey,
            async () => {
                const featuredProducts = await Product.find({
                    isActive: true,
                    isFeatured: true,
                    inStock: true
                })
                    .populate('createdBy', 'name email')
                    .select('name price originalPrice images category roastLevel flavorProfile description weight')
                    .sort({ createdAt: -1 })
                    .limit(Number(limit));

                return featuredProducts;
            },
            CACHE_TTL.SHORT
        );

        logger.debug('Featured products retrieved successfully', {
            count: products.length,
            fromCache: products.fromCache
        });

        res.json({
            success: true,
            products,
            section: 'featured',
            count: products.length
        });

    } catch (error: any) {
        LoggerService.errorLog('getFeaturedProducts', error, {
            query: req.query,
            userId: req.userId
        });

        res.status(500).json({
            success: false,
            message: 'Failed to retrieve featured products',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Get menu products with filtering and pagination
export const getMenuProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 12,
            category,
            roastLevel,
            minPrice,
            maxPrice,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const cacheKey = generateKey.menuProducts(`${page}:${limit}:${category}:${roastLevel}:${minPrice}:${maxPrice}:${sortBy}:${sortOrder}`);

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                const filter: any = {
                    isActive: true,
                    isFeatured: false,
                    inStock: true
                };

                // Apply filters based on query parameters
                if (category) filter.category = category;
                if (roastLevel) filter.roastLevel = roastLevel;

                // Price range filter
                if (minPrice || maxPrice) {
                    filter.price = {};
                    if (minPrice) filter.price.$gte = parseFloat(minPrice as string);
                    if (maxPrice) filter.price.$lte = parseFloat(maxPrice as string);
                }

                // Sort configuration
                const sort: any = {};
                sort[sortBy as string] = sortOrder === 'asc' ? 1 : -1;

                const products = await Product.find(filter)
                    .populate('createdBy', 'name email')
                    .select('name price originalPrice images category roastLevel flavorProfile weight description inStock')
                    .sort(sort)
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await Product.countDocuments(filter);

                // Get popular products for menu section
                const popularProducts = await getPopularProductsForMenu(6);

                return {
                    success: true,
                    popularProducts,
                    regularProducts: products,
                    pagination: {
                        total,
                        page: Number(page),
                        limit: Number(limit),
                        totalPages: Math.ceil(total / Number(limit))
                    },
                    filters: {
                        category,
                        roastLevel,
                        priceRange: { min: minPrice, max: maxPrice }
                    }
                };
            },
            CACHE_TTL.MEDIUM
        );

        res.json(responseData);

    } catch (error: any) {
        LoggerService.errorLog('getMenuProducts', error, {
            query: req.query,
            userId: req.userId
        });

        res.status(500).json({
            success: false,
            message: 'Failed to retrieve menu products',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Search products with text search and filters
export const searchProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            q: query,
            page = 1,
            limit = 12,
            category,
            roastLevel
        } = req.query;

        if (!query || (query as string).trim().length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Search query must be at least 2 characters long'
            });
        }

        const cacheKey = generateKey.productSearch(query as string, `${page}:${limit}:${category}:${roastLevel}`);

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                const searchFilter: any = {
                    isActive: true,
                    inStock: true,
                    $text: { $search: query as string }
                };

                // Additional filters for search
                if (category) searchFilter.category = category;
                if (roastLevel) searchFilter.roastLevel = roastLevel;

                const products = await Product.find(searchFilter)
                    .populate('createdBy', 'name email')
                    .select('name price originalPrice images category roastLevel flavorProfile weight description')
                    .sort({ score: { $meta: "textScore" } })
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await Product.countDocuments(searchFilter);

                // Get search suggestions for better UX
                const suggestions = await getSearchSuggestions(query as string);

                return {
                    success: true,
                    products,
                    searchInfo: {
                        query,
                        totalResults: total,
                        suggestions
                    },
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
        LoggerService.errorLog('searchProducts', error, {
            query: req.query.q,
            userId: req.userId
        });

        res.status(500).json({
            success: false,
            message: 'Search operation failed',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Get product details by ID
export const getProductById = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const cacheKey = generateKey.productDetail(id);

        const product = await cacheWithFallback(
            cacheKey,
            async () => {
                const productData = await Product.findById(id)
                    .populate('createdBy', 'name email')
                    .select('-searchKeywords');

                if (!productData) {
                    throw new Error('Product not found');
                }

                return productData;
            },
            CACHE_TTL.LONG
        );

        res.json({
            success: true,
            product
        });

    } catch (error: any) {
        LoggerService.errorLog('getProductById', error, {
            productId: req.params.id,
            userId: req.userId
        });

        if (error.message === 'Product not found') {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to retrieve product details',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Create new product (Admin only)
export const createProduct = async (req: AuthRequest, res: Response) => {
    try {
        const {
            name,
            description,
            price,
            originalPrice,
            category,
            roastLevel,
            flavorProfile,
            origin,
            weight,
            stockQuantity,
            isFeatured = false
        } = req.body;

        // Process uploaded images
        const images: string[] = [];
        if (req.files && Array.isArray(req.files)) {
            images.push(...req.files.map((file: Express.Multer.File) => getFileUrl(file.filename)));
        }

        // Validate required images
        if (images.length === 0) {
            // Clean up uploaded files if validation fails
            if (req.files && Array.isArray(req.files)) {
                for (const file of req.files) {
                    await deleteFile(file.filename);
                }
            }

            return res.status(400).json({
                success: false,
                message: 'At least one product image is required'
            });
        }

        // Create new product
        const product = new Product({
            name,
            description,
            price: parseFloat(price),
            originalPrice: originalPrice ? parseFloat(originalPrice) : undefined,
            category,
            roastLevel,
            flavorProfile: Array.isArray(flavorProfile)
                ? flavorProfile
                : flavorProfile?.split(',').map((f: string) => f.trim()) || [],
            origin,
            weight: parseFloat(weight),
            stockQuantity: parseInt(stockQuantity),
            isFeatured: isFeatured === 'true' || isFeatured === true,
            images,
            createdBy: req.userId
        });

        await product.save();

        // Clear relevant caches
        await clearProductCache();

        LoggerService.userLog(req.userId!, 'create_product', {
            productId: product._id.toString(),
            productName: product.name,
            isFeatured: product.isFeatured
        });

        logger.info('Product created successfully', {
            adminId: req.userId,
            productId: product._id.toString(),
            category: product.category
        });

        res.status(201).json({
            success: true,
            message: `Product "${product.name}" created successfully`,
            product: {
                id: product._id.toString(),
                name: product.name,
                category: product.category,
                isFeatured: product.isFeatured,
                images: product.images
            }
        });

    } catch (error: any) {
        // Clean up uploaded files on error
        if (req.files && Array.isArray(req.files)) {
            for (const file of req.files) {
                try {
                    await deleteFile(file.filename);
                } catch (deleteError) {
                    logger.error('Failed to delete file after product creation error', {
                        filename: file.filename,
                        error: deleteError
                    });
                }
            }
        }

        LoggerService.errorLog('createProduct', error, {
            adminId: req.userId,
            productData: req.body
        });

        res.status(500).json({
            success: false,
            message: 'Failed to create product',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Update existing product
export const updateProduct = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };

        // Find existing product - without cache for data consistency
        const existingProduct = await Product.findById(id);
        if (!existingProduct) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Process new images
        const newImages: string[] = [];
        if (req.files && Array.isArray(req.files)) {
            newImages.push(...req.files.map((file: Express.Multer.File) => getFileUrl(file.filename)));
        }

        // Update images array
        if (newImages.length > 0) {
            updateData.images = [...existingProduct.images, ...newImages];
        }

        // Process flavor profile
        if (updateData.flavorProfile && typeof updateData.flavorProfile === 'string') {
            updateData.flavorProfile = updateData.flavorProfile.split(',').map((f: string) => f.trim());
        }

        // Convert numeric fields
        if (updateData.price) updateData.price = parseFloat(updateData.price);
        if (updateData.originalPrice) updateData.originalPrice = parseFloat(updateData.originalPrice);
        if (updateData.weight) updateData.weight = parseFloat(updateData.weight);
        if (updateData.stockQuantity) updateData.stockQuantity = parseInt(updateData.stockQuantity);
        if (updateData.isFeatured) updateData.isFeatured = updateData.isFeatured === 'true';

        const updatedProduct = await Product.findByIdAndUpdate(
            id,
            updateData,
            { new: true, runValidators: true }
        ).populate('createdBy', 'name email');

        // Clear product cache
        await clearProductCache();

        LoggerService.userLog(req.userId!, 'update_product', {
            productId: id,
            productName: updatedProduct?.name,
            changes: Object.keys(updateData)
        });

        res.json({
            success: true,
            message: `Product "${updatedProduct?.name}" updated successfully`,
            product: updatedProduct
        });

    } catch (error: any) {
        LoggerService.errorLog('updateProduct', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'Failed to update product',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Delete product (Admin only)
export const deleteProduct = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        // Find product - without cache for consistency
        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Delete associated image files
        for (const imageUrl of product.images) {
            const filename = imageUrl.split('/').pop();
            if (filename) {
                try {
                    await deleteFile(filename);
                } catch (deleteError) {
                    logger.warn('Failed to delete product image file', {
                        filename,
                        error: deleteError
                    });
                }
            }
        }

        await Product.findByIdAndDelete(id);

        // Clear product cache
        await clearProductCache();

        LoggerService.userLog(req.userId!, 'delete_product', {
            productId: id,
            productName: product.name
        });

        logger.info('Product deleted successfully', {
            adminId: req.userId,
            productId: id,
            productName: product.name
        });

        res.json({
            success: true,
            message: `Product "${product.name}" deleted successfully`
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteProduct', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'Failed to delete product',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Delete specific product image
export const deleteProductImage = async (req: AuthRequest, res: Response) => {
    try {
        const { id, imageUrl } = req.params;

        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Remove image from array
        const updatedImages = product.images.filter(img => img !== imageUrl);

        // Ensure at least one image remains
        if (updatedImages.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete the last image. Products must have at least one image.'
            });
        }

        // Delete file from server
        const filename = imageUrl.split('/').pop();
        if (filename) {
            await deleteFile(filename);
        }

        // Update product with new images array
        product.images = updatedImages;
        await product.save();

        // Clear product cache
        await clearProductCache();

        LoggerService.userLog(req.userId!, 'delete_product_image', {
            productId: id,
            imageUrl
        });

        res.json({
            success: true,
            message: 'Image deleted successfully',
            product
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteProductImage', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'Failed to delete product image',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Get products for admin management
export const getAdminProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            isActive,
            isFeatured,
            category,
            search
        } = req.query;

        const cacheKey = generateKey.adminProducts(`${page}:${limit}:${isActive}:${isFeatured}:${category}:${search}`);

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                const filter: any = {};

                if (isActive !== undefined) filter.isActive = isActive === 'true';
                if (isFeatured !== undefined) filter.isFeatured = isFeatured === 'true';
                if (category) filter.category = category;

                // Search functionality
                if (search) {
                    filter.$or = [
                        { name: { $regex: search, $options: 'i' } },
                        { description: { $regex: search, $options: 'i' } }
                    ];
                }

                const products = await Product.find(filter)
                    .populate('createdBy', 'name email')
                    .sort({ createdAt: -1 })
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await Product.countDocuments(filter);

                return {
                    success: true,
                    products,
                    pagination: {
                        total,
                        page: Number(page),
                        limit: Number(limit),
                        totalPages: Math.ceil(total / Number(limit))
                    },
                    filters: {
                        isActive,
                        isFeatured,
                        category,
                        search
                    }
                };
            },
            CACHE_TTL.SHORT
        );

        res.json(responseData);

    } catch (error: any) {
        LoggerService.errorLog('getAdminProducts', error, {
            adminId: req.userId,
            query: req.query
        });

        res.status(500).json({
            success: false,
            message: 'Failed to retrieve admin products',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Helper function to get popular products for menu
const getPopularProductsForMenu = async (limit: number = 6): Promise<any[]> => {
    try {
        const cacheKey = generateKey.popularProducts(limit);

        return await cacheWithFallback(
            cacheKey,
            async () => {
                const popularProducts = await Product.find({
                    isActive: true,
                    isFeatured: false,
                    inStock: true
                })
                    .populate('createdBy', 'name')
                    .select('name price originalPrice images category roastLevel description')
                    .sort({
                        createdAt: -1
                    })
                    .limit(limit);

                return popularProducts;
            },
            CACHE_TTL.LONG
        );
    } catch (error) {
        logger.error('Error retrieving popular products', { error });
        return [];
    }
};

// Helper function to get search suggestions
const getSearchSuggestions = async (query: string): Promise<string[]> => {
    try {
        const cacheKey = `search_suggestions:${query}`;

        return await cacheWithFallback(
            cacheKey,
            async () => {
                const suggestions = await Product.aggregate([
                    {
                        $match: {
                            $text: { $search: query },
                            isActive: true
                        }
                    },
                    {
                        $unwind: "$searchKeywords"
                    },
                    {
                        $match: {
                            "searchKeywords": { $regex: query, $options: 'i' }
                        }
                    },
                    {
                        $group: {
                            _id: "$searchKeywords",
                            count: { $sum: 1 }
                        }
                    },
                    {
                        $sort: { count: -1 }
                    },
                    {
                        $limit: 5
                    },
                    {
                        $project: {
                            _id: 0,
                            keyword: "$_id"
                        }
                    }
                ]);

                return suggestions.map(s => s.keyword);
            },
            CACHE_TTL.MEDIUM
        );
    } catch (error) {
        logger.error('Error getting search suggestions', { error, query });
        return [];
    }
};

// Get popular products
export const getPopularProducts = async (req: AuthRequest, res: Response) => {
    try {
        const { limit = 6 } = req.query;

        const products = await getPopularProductsForMenu(Number(limit));

        res.json({
            success: true,
            products,
            section: 'popular'
        });

    } catch (error: any) {
        LoggerService.errorLog('getPopularProducts', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve popular products'
        });
    }
};