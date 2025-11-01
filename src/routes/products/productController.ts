// backend/src/controllers/productController.ts
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import Product from '../../models/product';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { deleteFile, getFileUrl } from '../../config/multerConfig';

// 🆕 تابع برای صفحه home - بخش offer (محصولات ویژه)
export const getFeaturedProducts = async (req: AuthRequest, res: Response) => {
    try {
        const { limit = 8 } = req.query;

        const products = await Product.find({
            isActive: true,
            isFeatured: true, // فقط محصولات ویژه
            inStock: true
        })
            .populate('createdBy', 'name')
            .select('name price originalPrice images category roastLevel flavorProfile description')
            .sort({ createdAt: -1 })
            .limit(Number(limit));

        res.json({
            success: true,
            products,
            section: 'offer'
        });

    } catch (error: any) {
        LoggerService.errorLog('getFeaturedProducts', error);
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت محصولات ویژه',
            error: error.message
        });
    }
};

// 🆕 تابع برای صفحه home - بخش menu (محصولات معمولی)
export const getMenuProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 12,
            category,
            roastLevel
        } = req.query;

        const filter: any = {
            isActive: true,
            isFeatured: false, // فقط محصولات معمولی
            inStock: true
        };

        if (category) filter.category = category;
        if (roastLevel) filter.roastLevel = roastLevel;

        const products = await Product.find(filter)
            .populate('createdBy', 'name')
            .select('name price originalPrice images category roastLevel flavorProfile weight description')
            .sort({ createdAt: -1 })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await Product.countDocuments(filter);

        // 🆕 گرفتن محصولات پرطرفدار برای بخش بالای منو
        const popularProducts = await getPopularProductsForMenu();

        res.json({
            success: true,
            popularProducts, // 🆕 محصولات پرطرفدار
            regularProducts: products, // محصولات معمولی
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            },
            section: 'menu'
        });

    } catch (error: any) {
        LoggerService.errorLog('getMenuProducts', error);
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت محصولات منو',
            error: error.message
        });
    }
};

// 🆕 تابع برای جستجو در منو (صفحه home)
export const searchProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            q: query,
            page = 1,
            limit = 12,
            category,
            roastLevel
        } = req.query;

        if (!query) {
            return res.status(400).json({
                success: false,
                message: 'عبارت جستجو الزامی است'
            });
        }

        const filter: any = {
            isActive: true,
            isFeatured: false, // فقط محصولات معمولی منو
            inStock: true
        };

        // جستجوی متن
        filter.$text = { $search: query as string };

        // فیلترهای اضافی
        if (category) filter.category = category;
        if (roastLevel) filter.roastLevel = roastLevel;

        const products = await Product.find(filter)
            .populate('createdBy', 'name')
            .select('name price originalPrice images category roastLevel flavorProfile weight description')
            .sort({ score: { $meta: "textScore" } })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await Product.countDocuments(filter);

        // 🆕 پیشنهادات جستجو
        const searchSuggestions = await getSearchSuggestions(query as string);

        res.json({
            success: true,
            products,
            searchInfo: {
                query,
                totalResults: total,
                suggestions: searchSuggestions
            },
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            },
            section: 'menu-search'
        });

    } catch (error: any) {
        LoggerService.errorLog('searchProducts', error);
        res.status(500).json({
            success: false,
            message: 'خطا در جستجوی محصولات',
            error: error.message
        });
    }
};

// 🆕 تابع کمکی برای محصولات پرطرفدار منو
const getPopularProductsForMenu = async (limit: number = 6) => {
    try {
        const products = await Product.find({
            isActive: true,
            isFeatured: false, // فقط محصولات معمولی
            inStock: true
        })
            .populate('createdBy', 'name')
            .select('name price originalPrice images category roastLevel description')
            .sort({
                // می‌توانید الگوریتم پرطرفدار بودن را اینجا پیاده‌سازی کنید
                // فعلاً بر اساس تاریخ ایجاد
                createdAt: -1
            })
            .limit(limit);

        return products;
    } catch (error) {
        logger.error('Error getting popular products:', error);
        return [];
    }
};

// 🆕 تابع برای محصولات پرطرفدار (API جداگانه)
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
            message: 'خطا در دریافت محصولات پرطرفدار',
            error: error.message
        });
    }
};

// 🆕 تابع کمکی برای پیشنهادات جستجو
const getSearchSuggestions = async (query: string): Promise<string[]> => {
    try {
        const suggestions = await Product.aggregate([
            {
                $match: {
                    $text: { $search: query },
                    isActive: true,
                    isFeatured: false // فقط از محصولات معمولی
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
    } catch (error) {
        logger.error('Error getting search suggestions:', error);
        return [];
    }
};

// ایجاد محصول جدید
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
            isFeatured = 'false' // پیش‌فرض محصول معمولی
        } = req.body;

        // بررسی فایل‌های آپلود شده
        const images: string[] = [];
        if (req.files && Array.isArray(req.files)) {
            images.push(...req.files.map((file: Express.Multer.File) => getFileUrl(file.filename)));
        }

        // ایجاد محصول
        const product = new Product({
            name,
            description,
            price: parseFloat(price),
            originalPrice: originalPrice ? parseFloat(originalPrice) : undefined,
            category,
            roastLevel,
            flavorProfile: Array.isArray(flavorProfile) ? flavorProfile : flavorProfile?.split(',').map((f: string) => f.trim()) || [],
            origin,
            weight: parseFloat(weight),
            stockQuantity: parseInt(stockQuantity),
            isFeatured: isFeatured === 'true', // تعیین محل نمایش
            images,
            createdBy: req.userId
        });

        await product.save();

        const destination = product.isFeatured ? 'پیشنهادات ویژه' : 'منو';

        LoggerService.userLog(req.userId!, 'create_product', {
            productId: product._id.toString(),
            productName: product.name,
            destination: destination
        });

        logger.info('Product created successfully', {
            adminId: req.userId,
            productId: product._id.toString(),
            isFeatured: product.isFeatured
        });

        res.status(201).json({
            success: true,
            message: `محصول با موفقیت ایجاد شد و به ${destination} اضافه گردید`,
            product: {
                id: product._id.toString(),
                name: product.name,
                isFeatured: product.isFeatured,
                destination: destination,
                images: product.images
            }
        });

    } catch (error: any) {
        // حذف فایل‌های آپلود شده در صورت خطا
        if (req.files && Array.isArray(req.files)) {
            for (const file of req.files) {
                try {
                    await deleteFile(file.filename);
                } catch (deleteError) {
                    logger.error('Failed to delete file after error:', {
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
            message: 'خطا در ایجاد محصول',
            error: error.message
        });
    }
};

// به‌روزرسانی محصول
export const updateProduct = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };

        // پیدا کردن محصول
        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'محصول یافت نشد'
            });
        }

        // پردازش فایل‌های جدید
        const newImages: string[] = [];
        if (req.files && Array.isArray(req.files)) {
            newImages.push(...req.files.map((file: Express.Multer.File) => getFileUrl(file.filename)));
        }

        // اگر فایل جدید آپلود شده، عکس‌های جدید را اضافه کن
        if (newImages.length > 0) {
            updateData.images = [...product.images, ...newImages];
        }

        // پردازش flavorProfile
        if (updateData.flavorProfile && typeof updateData.flavorProfile === 'string') {
            updateData.flavorProfile = updateData.flavorProfile.split(',').map((f: string) => f.trim());
        }

        // تبدیل اعداد
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

        const destination = updatedProduct?.isFeatured ? 'پیشنهادات ویژه' : 'منو';

        LoggerService.userLog(req.userId!, 'update_product', {
            productId: id,
            productName: updatedProduct?.name,
            newDestination: destination
        });

        res.json({
            success: true,
            message: `محصول با موفقیت به‌روزرسانی شد و به ${destination} منتقل گردید`,
            product: updatedProduct
        });

    } catch (error: any) {
        LoggerService.errorLog('updateProduct', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'خطا در به‌روزرسانی محصول',
            error: error.message
        });
    }
};

// حذف محصول
export const deleteProduct = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'محصول یافت نشد'
            });
        }

        // حذف فایل‌های عکس
        for (const imageUrl of product.images) {
            const filename = imageUrl.split('/').pop();
            if (filename) {
                try {
                    await deleteFile(filename);
                } catch (deleteError) {
                    logger.warn('Failed to delete product image:', {
                        filename,
                        error: deleteError
                    });
                }
            }
        }

        await Product.findByIdAndDelete(id);

        LoggerService.userLog(req.userId!, 'delete_product', {
            productId: id,
            productName: product.name
        });

        logger.info('Product deleted successfully', {
            adminId: req.userId,
            productId: id
        });

        res.json({
            success: true,
            message: 'محصول با موفقیت حذف شد'
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteProduct', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'خطا در حذف محصول',
            error: error.message
        });
    }
};

// دریافت تمام محصولات (برای ادمین)
export const getAdminProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            isActive,
            isFeatured
        } = req.query;

        const filter: any = {};

        if (isActive !== undefined) {
            filter.isActive = isActive === 'true';
        }

        if (isFeatured !== undefined) {
            filter.isFeatured = isFeatured === 'true';
        }

        const products = await Product.find(filter)
            .populate('createdBy', 'name email')
            .sort({ createdAt: -1 })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await Product.countDocuments(filter);

        res.json({
            success: true,
            products,
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            }
        });

    } catch (error: any) {
        LoggerService.errorLog('getAdminProducts', error, {
            adminId: req.userId
        });

        res.status(500).json({
            success: false,
            message: 'خطا در دریافت محصولات',
            error: error.message
        });
    }
};

// دریافت محصول بر اساس ID
export const getProductById = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const product = await Product.findById(id)
            .populate('createdBy', 'name');

        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'محصول یافت نشد'
            });
        }

        res.json({
            success: true,
            product
        });

    } catch (error: any) {
        LoggerService.errorLog('getProductById', error, {
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'خطا در دریافت محصول',
            error: error.message
        });
    }
};

// حذف عکس محصول
export const deleteProductImage = async (req: AuthRequest, res: Response) => {
    try {
        const { id, imageUrl } = req.params;

        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'محصول یافت نشد'
            });
        }

        // حذف عکس از آرایه
        const updatedImages = product.images.filter(img => img !== imageUrl);

        // حذف فایل از سرور
        const filename = imageUrl.split('/').pop();
        if (filename) {
            await deleteFile(filename);
        }

        product.images = updatedImages;
        await product.save();

        LoggerService.userLog(req.userId!, 'delete_product_image', {
            productId: id,
            imageUrl
        });

        res.json({
            success: true,
            message: 'عکس با موفقیت حذف شد',
            product
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteProductImage', error, {
            adminId: req.userId,
            productId: req.params.id
        });

        res.status(500).json({
            success: false,
            message: 'خطا در حذف عکس',
            error: error.message
        });
    }
};

// دریافت تمام محصولات با فیلتر (برای موارد عمومی)
export const getProducts = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            category,
            roastLevel,
            minPrice,
            maxPrice,
            inStock,
            isFeatured,
            search
        } = req.query;

        const filter: any = { isActive: true };

        if (category) filter.category = category;
        if (roastLevel) filter.roastLevel = roastLevel;
        if (inStock !== undefined) filter.inStock = inStock === 'true';
        if (isFeatured !== undefined) filter.isFeatured = isFeatured === 'true';

        // فیلتر قیمت
        if (minPrice || maxPrice) {
            filter.price = {};
            if (minPrice) filter.price.$gte = parseFloat(minPrice as string);
            if (maxPrice) filter.price.$lte = parseFloat(maxPrice as string);
        }

        // جستجو
        if (search) {
            filter.$text = { $search: search as string };
        }

        const sort: any = { createdAt: -1 };
        if (search) {
            sort.score = { $meta: "textScore" };
        }

        const products = await Product.find(filter)
            .populate('createdBy', 'name')
            .sort(sort)
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await Product.countDocuments(filter);

        res.json({
            success: true,
            products,
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            }
        });

    } catch (error: any) {
        LoggerService.errorLog('getProducts', error);
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت محصولات',
            error: error.message
        });
    }
};