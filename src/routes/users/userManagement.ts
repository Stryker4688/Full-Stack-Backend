// backend/src/routes/userManagement.ts
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireAdmin } from '../../middlewares/adminAuth';
import {
    getAllUsers,
    getUserById,
    loginAsUser,
    updateUserStatus,
    getUserStats
} from './userManagementController';

const router = express.Router();

// Admin and super admin can manage users
router.use(authenticateToken);
router.use(requireAdmin);

// User management routes
router.get('/users', getAllUsers);
router.get('/users/stats', getUserStats);
router.get('/users/:id', getUserById);
router.post('/users/login-as', loginAsUser);
router.patch('/users/:id/status', updateUserStatus);

export default router;