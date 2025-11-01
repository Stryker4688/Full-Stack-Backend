// backend/src/middlewares/testimonialValidation.ts
import { body } from 'express-validator';
import { validateRequest } from './validation';

export const testimonialValidation = [
    body('name')
        .notEmpty()
        .withMessage('نام الزامی است')
        .isLength({ min: 2, max: 50 })
        .withMessage('نام باید بین ۲ تا ۵۰ کاراکتر باشد')
        .trim(),

    body('email')
        .isEmail()
        .withMessage('ایمیل معتبر نیست')
        .normalizeEmail(),

    body('message')
        .notEmpty()
        .withMessage('متن نظر الزامی است')
        .isLength({ min: 10, max: 500 })
        .withMessage('متن نظر باید بین ۱۰ تا ۵۰۰ کاراکتر باشد')
        .trim(),

    body('rating')
        .optional()
        .isInt({ min: 1, max: 5 })
        .withMessage('امتیاز باید بین ۱ تا ۵ باشد'),

    validateRequest
];