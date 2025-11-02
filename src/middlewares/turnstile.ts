// backend/src/middlewares/turnstile.ts - Completely rewritten
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';

export const verifyTurnstile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Skip Turnstile verification in development mode
        if (process.env.NODE_ENV === 'development') {
            logger.debug('Turnstile verification skipped in development mode');
            return next();
        }

        // Extract Turnstile token from request body
        const turnstileToken = req.body['cf-turnstile-response'] || req.body.turnstileToken;

        if (!turnstileToken) {
            logger.warn('Turnstile token missing from request', {
                ip: req.ip,
                endpoint: req.path,
                userAgent: req.get('User-Agent')
            });

            return res.status(400).json({
                success: false,
                message: 'Please complete the security verification to continue',
                code: 'TURNSTILE_TOKEN_MISSING'
            });
        }

        // Prepare verification request to Cloudflare
        const formData = new FormData();
        formData.append('secret', process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY!);
        formData.append('response', turnstileToken);
        formData.append('remoteip', req.ip || '');

        // Verify token with Cloudflare Turnstile
        const verificationResponse = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            {
                method: 'POST',
                body: formData,
            }
        );

        const verificationResult = await verificationResponse.json();

        if (!verificationResult.success) {
            logger.warn('Turnstile verification failed', {
                ip: req.ip,
                endpoint: req.path,
                errorCodes: verificationResult['error-codes'],
                userAgent: req.get('User-Agent')
            });

            return res.status(400).json({
                success: false,
                message: 'Security verification failed. Please try again.',
                code: 'TURNSTILE_VERIFICATION_FAILED',
                errorCodes: verificationResult['error-codes']
            });
        }

        // Additional security checks
        if (verificationResult.hostname !== process.env.ALLOWED_DOMAIN) {
            logger.warn('Turnstile hostname mismatch', {
                ip: req.ip,
                expected: process.env.ALLOWED_DOMAIN,
                received: verificationResult.hostname
            });

            return res.status(400).json({
                success: false,
                message: 'Domain verification failed',
                code: 'DOMAIN_MISMATCH'
            });
        }

        logger.debug('Turnstile verification successful', {
            ip: req.ip,
            endpoint: req.path,
            hostname: verificationResult.hostname
        });

        // Store verification result in request for potential future use
        (req as any).turnstileVerified = true;
        (req as any).turnstileData = verificationResult;

        next();
    } catch (error: any) {
        logger.error('Turnstile verification process failed', {
            error: error.message,
            ip: req.ip,
            endpoint: req.path,
            stack: error.stack
        });

        return res.status(500).json({
            success: false,
            message: 'Security service temporarily unavailable. Please try again later.',
            code: 'TURNSTILE_SERVICE_ERROR'
        });
    }
};

// Optional: Strict Turnstile verification for sensitive endpoints
export const strictTurnstile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Always verify in strict mode, even in development
        const turnstileToken = req.body['cf-turnstile-response'] || req.body.turnstileToken;

        if (!turnstileToken) {
            logger.warn('Strict Turnstile - token missing', {
                ip: req.ip,
                endpoint: req.path
            });

            return res.status(400).json({
                success: false,
                message: 'Security verification required',
                code: 'STRICT_VERIFICATION_REQUIRED'
            });
        }

        const formData = new FormData();
        formData.append('secret', process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY!);
        formData.append('response', turnstileToken);
        formData.append('remoteip', req.ip || '');

        const verificationResponse = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            {
                method: 'POST',
                body: formData,
            }
        );

        const verificationResult = await verificationResponse.json();

        if (!verificationResult.success) {
            logger.warn('Strict Turnstile verification failed', {
                ip: req.ip,
                endpoint: req.path,
                errorCodes: verificationResult['error-codes']
            });

            return res.status(400).json({
                success: false,
                message: 'Security verification failed. Please refresh the page and try again.',
                code: 'STRICT_VERIFICATION_FAILED'
            });
        }

        // Additional strict checks
        const currentTime = Math.floor(Date.now() / 1000);
        const challengeTimestamp = verificationResult.challenge_ts;
        const timeDifference = currentTime - new Date(challengeTimestamp).getTime() / 1000;

        // Reject requests that took too long (more than 30 seconds)
        if (timeDifference > 30) {
            logger.warn('Strict Turnstile - challenge expired', {
                ip: req.ip,
                timeDifference,
                challengeTimestamp
            });

            return res.status(400).json({
                success: false,
                message: 'Security challenge expired. Please refresh and try again.',
                code: 'CHALLENGE_EXPIRED'
            });
        }

        logger.debug('Strict Turnstile verification passed', {
            ip: req.ip,
            endpoint: req.path
        });

        next();
    } catch (error: any) {
        logger.error('Strict Turnstile verification process failed', {
            error: error.message,
            ip: req.ip,
            endpoint: req.path
        });

        return res.status(500).json({
            success: false,
            message: 'Security verification service error',
            code: 'VERIFICATION_SERVICE_UNAVAILABLE'
        });
    }
};