// backend/src/middlewares/passwordResetValidation.ts - Completely rewritten
import { body } from 'express-validator';
import { validateRequest } from './validation';

export const passwordResetRequestValidation = [
    body('email')
        .isEmail()
        .withMessage('Valid email address is required')
        .normalizeEmail()
        .isLength({ max: 255 })
        .withMessage('Email address is too long')
        .custom((value: string) => {
            // Basic email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(value)) {
                throw new Error('Email format is invalid');
            }
            return true;
        }),

    validateRequest
];

export const verifyResetCodeValidation = [
    body('email')
        .isEmail()
        .withMessage('Valid email address is required')
        .normalizeEmail()
        .isLength({ max: 255 })
        .withMessage('Email address is too long'),

    body('code')
        .notEmpty()
        .withMessage('Verification code is required')
        .isLength({ min: 6, max: 6 })
        .withMessage('Verification code must be exactly 6 digits')
        .isNumeric()
        .withMessage('Verification code must contain only numbers')
        .custom((value: string) => {
            // Ensure code is exactly 6 digits
            const codeRegex = /^\d{6}$/;
            if (!codeRegex.test(value)) {
                throw new Error('Verification code format is invalid');
            }
            return true;
        }),

    validateRequest
];

export const resetPasswordValidation = [
    body('resetToken')
        .notEmpty()
        .withMessage('Reset token is required')
        .isJWT()
        .withMessage('Reset token format is invalid')
        .isLength({ min: 10 })
        .withMessage('Reset token appears to be invalid'),

    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .isLength({ max: 128 })
        .withMessage('Password is too long')
        .matches(/^(?=.*[a-z])/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/^(?=.*[A-Z])/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/^(?=.*\d)/)
        .withMessage('Password must contain at least one number')
        .matches(/^(?=.*[@$!%*?&])/)
        .withMessage('Password must contain at least one special character (@$!%*?&)')
        .custom((value: string, { req }) => {
            // Check for common passwords (basic example)
            const commonPasswords = [
                'password', '12345678', 'qwertyui', 'admin123', 'welcome1'
            ];

            if (commonPasswords.includes(value.toLowerCase())) {
                throw new Error('Password is too common. Please choose a stronger password.');
            }

            // Check if password contains user information
            const email = req.body?.email;
            if (email && value.toLowerCase().includes(email.split('@')[0].toLowerCase())) {
                throw new Error('Password should not contain your email address');
            }

            return true;
        }),

    body('confirmPassword')
        .notEmpty()
        .withMessage('Please confirm your password')
        .custom((value: string, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Passwords do not match');
            }
            return true;
        }),

    validateRequest
];

// Additional validation for password strength
export const validatePasswordStrength = [
    body('newPassword')
        .custom((value: string) => {
            // Calculate password strength score
            let score = 0;

            // Length check
            if (value.length >= 12) score += 2;
            else if (value.length >= 8) score += 1;

            // Character variety
            const hasLowercase = /[a-z]/.test(value);
            const hasUppercase = /[A-Z]/.test(value);
            const hasNumbers = /\d/.test(value);
            const hasSpecial = /[@$!%*?&]/.test(value);

            const varietyCount = [hasLowercase, hasUppercase, hasNumbers, hasSpecial]
                .filter(Boolean).length;

            score += varietyCount;

            // Sequential character check
            const sequentialRegex = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i;
            if (sequentialRegex.test(value)) {
                score -= 1;
            }

            // Repeated character check
            const repeatedRegex = /(.)\1{2,}/;
            if (repeatedRegex.test(value)) {
                score -= 1;
            }

            // Minimum strength requirement
            if (score < 4) {
                throw new Error('Password is too weak. Please use a stronger password with more variety.');
            }

            return true;
        })
];

// Validation for password change (when user is authenticated)
export const changePasswordValidation = [
    body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),

    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('New password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .withMessage('New password must contain uppercase, lowercase, number and special character')
        .custom((value: string, { req }) => {
            // Ensure new password is different from current password
            if (value === req.body.currentPassword) {
                throw new Error('New password must be different from current password');
            }
            return true;
        }),

    body('confirmPassword')
        .custom((value: string, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('New passwords do not match');
            }
            return true;
        }),

    validateRequest
];

// Validation utility functions
export const sanitizePasswordInput = (req: any, res: any, next: any) => {
    // Remove password from logs and unnecessary exposure
    if (req.body.newPassword) {
        req.body.newPassword = '[REDACTED]';
    }
    if (req.body.currentPassword) {
        req.body.currentPassword = '[REDACTED]';
    }
    if (req.body.confirmPassword) {
        req.body.confirmPassword = '[REDACTED]';
    }

    next();
};

// Export validation chains for different scenarios
export default {
    request: passwordResetRequestValidation,
    verify: verifyResetCodeValidation,
    reset: [...resetPasswordValidation, ...validatePasswordStrength],
    change: changePasswordValidation
};