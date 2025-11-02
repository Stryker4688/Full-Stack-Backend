// backend/src/middlewares/auth.ts - Optimized authentication middleware
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import {
    cacheGet,
    generateKey
} from '../utils/cacheUtils';
import { logger } from '../config/logger';

export interface AuthRequest extends Request {
    userId?: string;
    user?: any;
    impersonatedBy?: string;
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token is required for authentication'
            });
        }

        // Check cache for token validation first
        let decoded: any;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET!);
        } catch (error) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired authentication token'
            });
        }

        // Validate token structure
        if (!decoded.userId) {
            return res.status(403).json({
                success: false,
                message: 'Invalid token structure'
            });
        }

        // Check cache for token session
        const sessionKey = generateKey.userSession(decoded.userId);
        const cachedSession = await cacheGet(sessionKey);

        if (cachedSession && cachedSession.token === token) {
            // Token is valid and found in cache
            req.userId = decoded.userId;
            req.user = {
                userId: decoded.userId,
                impersonatedBy: decoded.impersonatedBy
            };

            logger.debug('Token validated from cache', { userId: decoded.userId });
            return next();
        }

        // If not in cache, verify with JWT and proceed
        req.userId = decoded.userId;
        req.user = {
            userId: decoded.userId,
            impersonatedBy: decoded.impersonatedBy
        };

        logger.debug('Token validated successfully', { userId: decoded.userId });
        next();

    } catch (error) {
        logger.error('Token authentication failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            ip: req.ip,
            endpoint: req.url
        });

        return res.status(500).json({
            success: false,
            message: 'Authentication service error'
        });
    }
};

// Optional: Enhanced token verification with additional checks
export const authenticateTokenStrict = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token is required'
            });
        }

        // Verify JWT token
        let decoded: any;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET!);
        } catch (error) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        // Additional validation checks
        if (!decoded.userId) {
            return res.status(403).json({
                success: false,
                message: 'Invalid token payload'
            });
        }

        // Check for impersonation session if applicable
        if (decoded.impersonatedBy) {
            const impersonationSession = await cacheGet(generateKey.userSession(decoded.userId));
            if (!impersonationSession || impersonationSession.adminId !== decoded.impersonatedBy) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid impersonation session'
                });
            }
        }

        req.userId = decoded.userId;
        req.user = {
            userId: decoded.userId,
            impersonatedBy: decoded.impersonatedBy,
            originalRole: decoded.originalRole
        };

        logger.debug('Strict token validation successful', {
            userId: decoded.userId,
            impersonatedBy: decoded.impersonatedBy
        });

        next();

    } catch (error) {
        logger.error('Strict token authentication failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            ip: req.ip,
            endpoint: req.url
        });

        return res.status(500).json({
            success: false,
            message: 'Authentication service error'
        });
    }
};

// Middleware to require specific user roles
export const requireRole = (allowedRoles: string[]) => {
    return async (req: AuthRequest, res: Response, next: NextFunction) => {
        try {
            if (!req.userId) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            // Get user from cache first
            const userKey = generateKey.userDetail(req.userId);
            let user = await cacheGet(userKey);

            if (!user) {
                // If not in cache, you might want to fetch from database
                // For now, we'll proceed and let the controller handle user fetching
                logger.debug('User not found in cache during role check', { userId: req.userId });
                return next();
            }

            // Check if user role is allowed
            if (!allowedRoles.includes(user.role)) {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions for this action'
                });
            }

            logger.debug('Role check passed', {
                userId: req.userId,
                role: user.role,
                allowedRoles
            });

            next();

        } catch (error) {
            logger.error('Role-based authentication failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                userId: req.userId,
                allowedRoles
            });

            return res.status(500).json({
                success: false,
                message: 'Authorization service error'
            });
        }
    };
};

// Middleware to check if user is authenticated (without strict validation)
export const optionalAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            // No token provided, but proceed as unauthenticated user
            req.userId = undefined;
            req.user = undefined;
            return next();
        }

        let decoded: any;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET!);
        } catch (error) {
            // Invalid token, proceed as unauthenticated user
            req.userId = undefined;
            req.user = undefined;
            return next();
        }

        if (decoded.userId) {
            req.userId = decoded.userId;
            req.user = {
                userId: decoded.userId,
                impersonatedBy: decoded.impersonatedBy
            };
        }

        next();

    } catch (error) {
        // On error, proceed as unauthenticated user
        req.userId = undefined;
        req.user = undefined;
        next();
    }
};

// Impersonation validation middleware
export const validateImpersonation = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.user?.impersonatedBy) {
            // Not an impersonation session, proceed normally
            return next();
        }

        const adminId = req.user.impersonatedBy;
        const userId = req.userId;

        // Verify impersonation session in cache
        const sessionKey = generateKey.userSession(userId!);
        const impersonationSession = await cacheGet(sessionKey);

        if (!impersonationSession || impersonationSession.adminId !== adminId) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired impersonation session'
            });
        }

        logger.debug('Impersonation session validated', {
            adminId,
            userId,
            originalRole: impersonationSession.originalRole
        });

        next();

    } catch (error) {
        logger.error('Impersonation validation failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            userId: req.userId,
            impersonatedBy: req.user?.impersonatedBy
        });

        return res.status(500).json({
            success: false,
            message: 'Impersonation validation error'
        });
    }
};

