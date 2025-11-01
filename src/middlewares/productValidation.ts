// backend/src/middlewares/productValidation.ts - به‌روزرسانی شده
import { body } from 'express-validator';
import { validateRequest } from './validation';

export const productValidation = [
    body('name')
        .notEmpty()
        .withMessage('نام محصول الزامی است')
        .isLength({ min: 2, max: 100 })
        .withMessage('نام محصول باید بین ۲ تا ۱۰۰ کاراکتر باشد')
        .trim(),

    body('description')
        .notEmpty()
        .withMessage('توضیحات محصول الزامی است')
        .isLength({ min: 10, max: 1000 })
        .withMessage('توضیحات باید بین ۱۰ تا ۱۰۰۰ کاراکتر باشد')
        .trim(),

    body('price')
        .isFloat({ min: 0 })
        .withMessage('قیمت باید عددی مثبت باشد'),

    body('originalPrice')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('قیمت اصلی باید عددی مثبت باشد'),

    body('category')
        .isIn(['coffee_beans', 'brewing_equipment', 'accessories', 'gift_sets'])
        .withMessage('دسته‌بندی معتبر نیست'),

    body('roastLevel')
        .isIn(['light', 'medium', 'dark', 'espresso'])
        .withMessage('سطح برشتگی معتبر نیست'),

    body('weight')
        .isFloat({ min: 0 })
        .withMessage('وزن باید عددی مثبت باشد'),

    body('stockQuantity')
        .isInt({ min: 0 })
        .withMessage('تعداد موجودی باید عدد صحیح مثبت باشد'),

    body('isFeatured')
        .optional()
        .isBoolean()
        .withMessage('وضعیت محصول ویژه باید boolean باشد'),

    validateRequest
];