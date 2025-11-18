// backend/src/middleware/validation.ts
import { Request, Response, NextFunction } from 'express';
import { validationResult, body } from 'express-validator';

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      message: 'Validation failed',
      errors: errors.array()
    });
    return;
  }
  next();
};

export const registerValidation = [
  body('name')
    .notEmpty()
    .withMessage('نام الزامی است')
    .isLength({ min: 2, max: 50 })
    .withMessage('نام باید بین ۲ تا ۵۰ کاراکتر باشد')
    .trim(),

  body('email')
    .isEmail()
    .withMessage('ایمیل معتبر نیست')
    .notEmpty()
    .withMessage('ایمیل الزامی هست'),

  body('password')
    .isLength({ min: 6 })
    .withMessage('رمز عبور باید حداقل ۶ کاراکتر باشد')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('رمز عبور باید شامل حروف بزرگ، کوچک و اعداد باشد'),
  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('rememberMe باید boolean باشد')
];

export const loginValidation = [
  body('email')
    .isEmail()
    .withMessage('ایمیل معتبر نیست'),

  body('password')
    .notEmpty()
    .withMessage('رمز عبور الزامی است')
];

export const taskValidation = [
  body('title')
    .notEmpty()
    .withMessage('عنوان تسک الزامی است')
    .isLength({ min: 1, max: 100 })
    .withMessage('عنوان باید بین ۱ تا ۱۰۰ کاراکتر باشد')
    .trim(),

  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('توضیحات نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد')
    .trim(),

  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('اولویت باید low, medium یا high باشد'),

  body('dueDate')
    .optional()
    .isISO8601()
    .withMessage('تاریخ باید معتبر باشد'),
  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('rememberMe باید boolean باشد')
];