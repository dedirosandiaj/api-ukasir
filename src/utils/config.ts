import { Pool } from 'pg';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 5000
});

// Enkripsi AES-256-CBC
const ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_KEY = process.env.CONFIG_ENCRYPTION_KEY || 'default-fallback-key-should-be-32-bytes!';

/**
 * Melakukan enkripsi teks menggunakan AES-256-CBC
 */
export const encrypt = (text: string): string => {
    try {
        const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return `${iv.toString('hex')}:${encrypted}`;
    } catch (e) {
        console.error('Gagal melakukan enkripsi:', e);
        return text;
    }
};

/**
 * Melakukan dekripsi teks hasil enkripsi AES-256-CBC.
 * Jika format tidak valid (data lama tidak terenkripsi), akan mengembalikan teks asli secara aman.
 */
export const decrypt = (text: string): string => {
    try {
        const parts = text.split(':');
        if (parts.length !== 2) {
            return text; // Nilai lama belum terenkripsi
        }
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];
        const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return text; // Jika gagal dekripsi, anggap data lama tidak terenkripsi
    }
};

/**
 * Mengambil nilai konfigurasi dari database berdasarkan key dan mendekripsinya secara otomatis.
 * Jika key tidak ditemukan, akan mengembalikan defaultValue.
 */
export const getConfig = async (key: string, defaultValue: string = ''): Promise<string> => {
    let client;
    try {
        client = await pool.connect();
        const res = await client.query('SELECT value FROM app_config WHERE key = $1 LIMIT 1', [key]);
        if (res.rows.length > 0) {
            return decrypt(res.rows[0].value);
        }
    } catch (e) {
        console.error(`Gagal memuat konfigurasi untuk key "${key}":`, e);
    } finally {
        if (client) client.release();
    }
    return defaultValue;
};

/**
 * Mengenkripsi nilai konfigurasi dan menyimpannya ke database (Upsert).
 */
export const setConfig = async (key: string, value: string): Promise<void> => {
    let client;
    try {
        const encryptedValue = encrypt(value);
        client = await pool.connect();
        await client.query(
            `INSERT INTO app_config (key, value, updated_at) 
             VALUES ($1, $2, NOW()) 
             ON CONFLICT (key) 
             DO UPDATE SET value = $2, updated_at = NOW()`,
            [key, encryptedValue]
        );
    } catch (e) {
        console.error(`Gagal menyimpan konfigurasi untuk key "${key}":`, e);
        throw e;
    } finally {
        if (client) client.release();
    }
};
