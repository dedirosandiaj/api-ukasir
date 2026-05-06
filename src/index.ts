import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import v1Routes from './v1';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Rate limiting - 100 requests per 15 minutes per IP
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Trust proxy for Coolify/Vercel
app.set('trust proxy', 1);

// Health check
app.get('/', (req: Request, res: Response) => {
    res.json({
        message: 'Ukasir API is running',
        version: '1.0.0'
    });
});

// Mount v1 routes
app.use(v1Routes);

// Vercel requires exporting the app
export default app;

// Local development
if (!process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}
