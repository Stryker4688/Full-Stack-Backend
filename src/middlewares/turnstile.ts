// backend/src/middlewares/turnstile.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';

export const verifyTurnstile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // ✅ اگر در حالت توسعه هستیم، skip شود
        if (process.env.NODE_ENV === 'development') {
            logger.debug('Turnstile skipped in development mode');
            return next();
        }

        // 🔥 تغییر این خط - استفاده از نام درست فیلد
        const turnstileToken = req.body['cf-turnstile-response'] || req.body.turnstileToken;

        // اگر توکن Turnstile وجود ندارد
        if (!turnstileToken) {
            logger.warn('Turnstile token missing', { ip: req.ip, endpoint: req.path });
            return res.status(400).json({
                message: 'لطفاً تأیید کنید که شما ربات نیستید'
            });
        }

        // بقیه کد بدون تغییر...
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
                message: 'تأیید امنیتی ناموفق بود. لطفاً دوباره تلاش کنید.'
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
            message: 'خطا در سرویس امنیتی. لطفاً دوباره تلاش کنید.'
        });
    }
};