const crypto = require('crypto');
const API_KEY = 'ukasir_dev_7a8f9b2c4d6e1g3h5i7j9k0l2m4n6o8p';
const API_SECRET = 'sk_dev_efceec2c7acd554fa08ee46d771b90e0f2e68a2be84be0af2b24c5fb0db99232';
const TOKEN_NUMBER = '9190-4957-3083-9321';
const BASE_URL = 'https://development.api.ukasir.id';

const payload = {
    token_number: TOKEN_NUMBER,
    gross_amount: 15000
};

const timestamp = Math.floor(Date.now() / 1000).toString();
const bodyString = JSON.stringify(payload);
const signPayload = `${API_KEY}:${timestamp}:${bodyString}`;
const signature = crypto.createHmac('sha256', API_SECRET).update(signPayload).digest('hex');

fetch(`${BASE_URL}/v1/cashier-transactions`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'x-timestamp': timestamp,
        'x-signature': signature
    },
    body: bodyString
}).then(async res => {
    console.log("Status:", res.status);
    console.log("Response:", await res.text());
}).catch(console.error);
