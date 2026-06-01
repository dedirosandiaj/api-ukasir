import { Router } from 'express';
import authRoutes from './routes/auth';
import tokenRoutes from './routes/token';
import productRoutes from './routes/products';
import notificationRoutes from './routes/notifications';

const router = Router();

// Mount all v1 routes
router.use(authRoutes);
router.use(tokenRoutes);
router.use(productRoutes);
router.use(notificationRoutes);

export default router;
