import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from 'k6/crypto';

// CONFIGURATION
// K6 akan menggunakan BASE_URL dari env, atau default ke localhost
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
// Anda harus mengisi API_KEY dan API_SECRET yang sama dengan di .env
const API_KEY = __ENV.API_KEY || 'your_default_api_key';
const API_SECRET = __ENV.API_SECRET || 'your_default_api_secret';
// Token merchant yang valid untuk dites
const TOKEN_NUMBER = __ENV.TOKEN_NUMBER || '1111-2222-3333-4444';

export const options = {
  // Skenario: 50 Virtual Users berjalan selama 30 detik
  vus: 50,
  duration: '30s',
  thresholds: {
    // 95% requests harus selesai di bawah 500ms
    http_req_duration: ['p(95)<500'],
  },
};

function generateAuthHeaders(bodyPayload) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyString = Object.keys(bodyPayload).length > 0 ? JSON.stringify(bodyPayload) : "{}";
    const payload = `${API_KEY}:${timestamp}:${bodyString}`;
    
    // Generate HMAC SHA256 signature (Hex)
    const signature = crypto.hmac('sha256', API_SECRET, payload, 'hex');

    return {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'x-timestamp': timestamp,
        'x-signature': signature
    };
}

export default function () {
    // 1. Uji POST /api/v1/cashier-transactions (Create Transaction)
    const createPayload = {
        token_number: TOKEN_NUMBER,
        gross_amount: Math.floor(Math.random() * 50000) + 10000 // Random amount antara 10k-60k
    };

    const createHeaders = generateAuthHeaders(createPayload);
    
    const createRes = http.post(`${BASE_URL}/api/v1/cashier-transactions`, JSON.stringify(createPayload), {
        headers: createHeaders
    });

    check(createRes, {
        'create transaction status is 201': (r) => r.status === 201,
        'create transaction has order_id': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.success === true && body.data.order_id !== undefined;
            } catch (e) {
                return false;
            }
        }
    });

    // Simulasi jeda user
    sleep(1);
}
