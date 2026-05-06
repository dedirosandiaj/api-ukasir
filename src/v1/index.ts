import { Router } from 'express';
import authRoutes from './routes/auth';
import tokenRoutes from './routes/token';

const router = Router();

// Mount all v1 routes
router.use(authRoutes);
router.use(tokenRoutes);

export default router;
