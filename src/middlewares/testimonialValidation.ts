// backend/src/middlewares/testimonialValidation.ts
import { body } from 'express-validator';
import { validateRequest } from './validation';

// Validation rules for testimonial submission
export const testimonialValidation = [
    body('name')
        .notEmpty()
        .withMessage('Name is required')
        .isLength({ min: 2, max: 50 })
        .withMessage('Name must be between 2 and 50 characters')
        .trim(),

    body('email')
        .isEmail()
        .withMessage('Valid email is required')
        .normalizeEmail(),

    body('message')
        .notEmpty()
        .withMessage('Testimonial message is required')
        .isLength({ min: 10, max: 500 })
        .withMessage('Message must be between 10 and 500 characters')
        .trim(),

    body('rating')
        .optional()
        .isInt({ min: 1, max: 5 })
        .withMessage('Rating must be between 1 and 5'),

    validateRequest
];