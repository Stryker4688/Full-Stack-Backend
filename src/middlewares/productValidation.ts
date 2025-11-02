// backend/src/middlewares/productValidation.ts - Updated
import { body } from 'express-validator';
import { validateRequest } from './validation';

export const productValidation = [
    body('name')
        .notEmpty()
        .withMessage('Product name is required')
        .isLength({ min: 2, max: 100 })
        .withMessage('Product name must be between 2 and 100 characters')
        .trim(),

    body('description')
        .notEmpty()
        .withMessage('Product description is required')
        .isLength({ min: 10, max: 1000 })
        .withMessage('Description must be between 10 and 1000 characters')
        .trim(),

    body('price')
        .isFloat({ min: 0 })
        .withMessage('Price must be a positive number'),

    body('originalPrice')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Original price must be a positive number'),

    body('category')
        .isIn(['coffee_beans', 'brewing_equipment', 'accessories', 'gift_sets'])
        .withMessage('Invalid category'),

    body('roastLevel')
        .isIn(['light', 'medium', 'dark', 'espresso'])
        .withMessage('Invalid roast level'),

    body('weight')
        .isFloat({ min: 0 })
        .withMessage('Weight must be a positive number'),

    body('stockQuantity')
        .isInt({ min: 0 })
        .withMessage('Stock quantity must be a positive integer'),

    body('isFeatured')
        .optional()
        .isBoolean()
        .withMessage('Featured status must be boolean'),

    validateRequest
];