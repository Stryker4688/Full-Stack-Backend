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

// فقط سوپر ادمین می‌تواند ادمین ایجاد/حذف کند
router.use(authenticateToken);
router.use(requireSuperAdmin);

// مدیریت ادمین‌ها
router.post('/admins', createAdmin);
router.get('/admins', getAdmins);
router.delete('/admins/:id', deleteAdmin);
router.patch('/admins/:id/status', toggleAdminStatus);

export default router;