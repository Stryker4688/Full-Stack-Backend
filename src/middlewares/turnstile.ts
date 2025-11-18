// backend/src/middlewares/turnstile.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';

// Cloudflare Turnstile CAPTCHA verification middleware
export const verifyTurnstile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // ✅ Skip in development mode
        if (process.env.NODE_ENV === 'development') {
            logger.debug('Turnstile skipped in development mode');
            return next();
        }

        // 🔥 Change this line - using correct field name
        const turnstileToken = req.body['cf-turnstile-response'] || req.body.turnstileToken;

        // If Turnstile token is missing
        if (!turnstileToken) {
            logger.warn('Turnstile token missing', { ip: req.ip, endpoint: req.path });
            return res.status(400).json({
                message: 'Please verify that you are not a robot'
            });
        }

        // Verify token with Cloudflare Turnstile API
        const formData = new FormData();
        formData.append('secret', process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY!);
        formData.append('response', turnstileToken);
        formData.append('remoteip', req.ip || '');

        const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
        });

        const outcome = await result.json();

        if (!outcome.success) {
            logger.warn('Turnstile verification failed', {
                ip: req.ip,
                endpoint: req.path,
                errorCodes: outcome['error-codes']
            });

            return res.status(400).json({
                message: 'Security verification failed. Please try again.'
            });
        }

        logger.debug('Turnstile verification successful', {
            ip: req.ip,
            endpoint: req.path
        });

        next();
    } catch (error) {
        logger.error('Turnstile verification error', { error, ip: req.ip });
        return res.status(500).json({
            message: 'Error in security service. Please try again.'
        });
    }
};