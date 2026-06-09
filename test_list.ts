import http from 'http';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

const API_KEY = process.env.API_KEY!;
const API_SECRET = process.env.API_SECRET!;
const TEST_TOKEN = '9190-4957-3083-9321';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: false });

// NOTE: verifyApiAuth always uses JSON.stringify(req.body || {}) = "{}" for body
// So for GET requests, the signature payload uses "{}" (not empty string)
function signedRequest(method: string, path: string): Promise<{ status: number; data: any }> {
    return new Promise((resolve) => {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyString = '{}'; // always "{}" - matches server-side JSON.stringify(req.body || {})
        const payload = `${API_KEY}:${timestamp}:${bodyString}`;
        const signature = crypto.createHmac('sha256', API_SECRET).update(payload).digest('hex');
        const headers: any = {
            'Content-Type': 'application/json',
            'x-api-key': API_KEY,
            'x-timestamp': timestamp,
            'x-signature': signature
        };
        const req = http.request({ hostname: 'localhost', port: 3005, path: `/v1${path}`, method, headers }, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode!, data: JSON.parse(body) }); }
                catch { resolve({ status: res.statusCode!, data: body }); }
            });
        });
        req.on('error', err => resolve({ status: 500, data: err.message }));
        req.end();
    });
}

async function run() {
    console.log('=== Verifikasi GET /v1/cashier-transactions?token_number= ===\n');

    const client = await pool.connect();
    const ts = Date.now();
    const id1 = `TRX-LST-${ts}-1`;
    const id2 = `TRX-LST-${ts}-2`;

    // Sisipkan 2 dummy transaksi
    await client.query(
        `INSERT INTO cashier_transactions (id,order_id,token_number,gross_amount,payment_status) VALUES
         (gen_random_uuid(),$1,$2,10000,'pending'),(gen_random_uuid(),$3,$4,25000,'paid')`,
        [id1, TEST_TOKEN, id2, TEST_TOKEN]
    );
    console.log('1. 2 dummy transaksi disisipkan ke DB.\n');

    // Test 1 — tanpa token_number (harus 400)
    const noToken = await signedRequest('GET', '/cashier-transactions');
    console.log('2. Tanpa token_number (Expected 400):', noToken.status, noToken.data);

    // Test 2 — format token salah (harus 400)
    const badFmt = await signedRequest('GET', '/cashier-transactions?token_number=INVALID');
    console.log('3. Format token salah (Expected 400):', badFmt.status, badFmt.data);

    // Test 3 — token benar (harus 200 + array data)
    const ok = await signedRequest('GET', `/cashier-transactions?token_number=${TEST_TOKEN}`);
    console.log('4. Token benar (Expected 200):', ok.status);
    if (Array.isArray(ok.data?.data)) {
        console.log('   Jumlah data:', ok.data.data.length);
        console.log('   Sample order_id:', ok.data.data[0]?.order_id);
        console.log('   Sample status:  ', ok.data.data[0]?.payment_status);
    } else {
        console.log('   Response:', ok.data);
    }

    // Bersihkan dummy
    await client.query('DELETE FROM cashier_transactions WHERE order_id IN ($1,$2)', [id1, id2]);
    client.release();
    await pool.end();

    console.log('\n5. Data dummy dibersihkan dari DB.');
    console.log('\n=== Verifikasi Selesai ===');
}

run();
