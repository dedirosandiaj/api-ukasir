import { Router } from 'express';
import authRoutes from './routes/auth';
import tokenRoutes from './routes/token';
import productRoutes from './routes/products';
import notificationRoutes from './routes/notifications';
import bankEwalletRoutes from './routes/bank_ewallets';
import qrisActivationRoutes from './routes/qris_activations';
import cashierTransactionRoutes from './routes/cashier_transactions';
import withdrawalRoutes from './routes/withdrawals';
import soundRoutes from './routes/sounds';
import backupRoutes from './routes/backups';
import regionsRoutes from './routes/regions';

const router = Router();

// Mount all v1 routes
router.use(authRoutes);
router.use(tokenRoutes);
router.use(productRoutes);
router.use(notificationRoutes);
router.use(bankEwalletRoutes);
router.use(qrisActivationRoutes);
router.use(cashierTransactionRoutes);
router.use(withdrawalRoutes);
router.use(soundRoutes);
router.use(backupRoutes);
router.use(regionsRoutes);

export default router;
