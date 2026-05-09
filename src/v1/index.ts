import { Router } from 'express';
import authRoutes from './routes/auth';
import tokenRoutes from './routes/token';
import productRoutes from './routes/products';

const router = Router();

// Mount all v1 routes
router.use(authRoutes);
router.use(tokenRoutes);
router.use(productRoutes);

export default router;
