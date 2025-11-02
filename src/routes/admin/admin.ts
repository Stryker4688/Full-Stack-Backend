// backend/src/routes/admin/admin.ts
import express from 'express';
import { authenticateToken } from '../../middlewares/auth';
import { requireSuperAdmin } from '../../middlewares/adminAuth';
import {
    createAdmin,
    getAdmins,
    deleteAdmin,
    toggleAdminStatus
} from './adminController';

const router = express.Router();

// Only super admin can create/delete admins
router.use(authenticateToken);
router.use(requireSuperAdmin);

// Admin management
router.post('/admins', createAdmin);
router.get('/admins', getAdmins);
router.delete('/admins/:id', deleteAdmin);
router.patch('/admins/:id/status', toggleAdminStatus);

export default router;