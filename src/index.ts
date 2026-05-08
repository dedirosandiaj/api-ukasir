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
app.use(cors({
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'x-api-key', 'x-timestamp', 'x-signature']
}));
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

// Payment status page
app.get('/payment-status', (req: Request, res: Response) => {
    const { order_id, status_code, transaction_status, fraud_status } = req.query;
    
    const html = `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Status - Ukasir</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        .icon {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 40px;
        }
        .success { background: #d4edda; color: #155724; }
        .pending { background: #fff3cd; color: #856404; }
        .failed { background: #f8d7da; color: #721c24; }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .status-text { color: #666; font-size: 16px; margin-bottom: 30px; line-height: 1.6; }
        .details {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: left;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e9ecef;
        }
        .detail-row:last-child { border-bottom: none; }
        .detail-label { color: #666; font-weight: 500; }
        .detail-value { color: #333; font-weight: 600; }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
            margin: 5px;
        }
        .btn:hover { background: #5568d3; transform: translateY(-2px); }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #5a6268; }
        .loading {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        ${getStatusIcon(transaction_status as string)}
        <h1>${getStatusTitle(transaction_status as string)}</h1>
        <p class="status-text">${getStatusMessage(transaction_status as string)}</p>
        
        <div class="details">
            <div class="detail-row">
                <span class="detail-label">Order ID:</span>
                <span class="detail-value">${order_id || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status Code:</span>
                <span class="detail-value">${status_code || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Transaction Status:</span>
                <span class="detail-value">${formatStatus(transaction_status as string)}</span>
            </div>
            ${fraud_status ? `
            <div class="detail-row">
                <span class="detail-label">Fraud Status:</span>
                <span class="detail-value">${fraud_status}</span>
            </div>
            ` : ''}
        </div>

        ${getButtons(transaction_status as string)}
    </div>

    <script>
        // Auto redirect to app if payment is successful
        ${transaction_status === 'settlement' || transaction_status === 'capture' ? `
        setTimeout(() => {
            if (confirm('Payment successful! Open Ukasir app?')) {
                window.location.href = 'ukasir://';
            }
        }, 3000);
        ` : ''}
    </script>
</body>
</html>
    `;
    
    res.send(html);
});

// Helper functions for payment status page
function getStatusIcon(status: string): string {
    switch(status) {
        case 'settlement':
        case 'capture':
            return '<div class="icon success">✓</div>';
        case 'pending':
            return '<div class="icon pending loading">⏳</div>';
        case 'cancel':
        case 'expire':
        case 'deny':
            return '<div class="icon failed">✕</div>';
        default:
            return '<div class="icon pending">ℹ</div>';
    }
}

function getStatusTitle(status: string): string {
    switch(status) {
        case 'settlement':
        case 'capture':
            return 'Payment Successful!';
        case 'pending':
            return 'Waiting for Payment';
        case 'cancel':
            return 'Payment Cancelled';
        case 'expire':
            return 'Payment Expired';
        case 'deny':
            return 'Payment Denied';
        default:
            return 'Payment Status';
    }
}

function getStatusMessage(status: string): string {
    switch(status) {
        case 'settlement':
        case 'capture':
            return 'Your payment has been confirmed. You will receive your activation token via email shortly.';
        case 'pending':
            return 'Please complete your payment before the deadline. Check your email for payment instructions.';
        case 'cancel':
            return 'Your payment was cancelled. You can register again with a new order.';
        case 'expire':
            return 'Your payment link has expired. Please register again to get a new payment link.';
        case 'deny':
            return 'Your payment was denied by the bank. Please try a different payment method.';
        default:
            return 'Your payment is being processed. Please wait for confirmation.';
    }
}

function formatStatus(status: string): string {
    if (!status) return 'Unknown';
    return status.charAt(0).toUpperCase() + status.slice(1);
}

function getButtons(status: string): string {
    switch(status) {
        case 'settlement':
        case 'capture':
            return '<a href="mailto:support@ukasir.id" class="btn">Contact Support</a>';
        case 'pending':
            return '<a href="mailto:support@ukasir.id" class="btn">Need Help?</a>';
        case 'cancel':
        case 'expire':
        case 'deny':
            return '<a href="https://ukasir.id" class="btn">Try Again</a><a href="mailto:support@ukasir.id" class="btn btn-secondary">Contact Support</a>';
        default:
            return '<a href="mailto:support@ukasir.id" class="btn">Contact Support</a>';
    }
}

// Mount v1 routes
app.use('/v1', v1Routes);

// Vercel requires exporting the app
export default app;

// Local development
if (!process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}
