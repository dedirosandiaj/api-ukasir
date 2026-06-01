import dotenv from 'dotenv';

dotenv.config();

/**
 * Mengambil nilai konfigurasi langsung dari environment variables (process.env).
 * Jika key tidak ditemukan, akan mengembalikan defaultValue.
 */
export const getConfig = async (key: string, defaultValue: string = ''): Promise<string> => {
    return process.env[key] || defaultValue;
};

/**
 * Stub untuk setConfig agar tidak terjadi error kompilasi jika ada file lain yang mengimpornya.
 */
export const setConfig = async (key: string, value: string): Promise<void> => {
    process.env[key] = value;
};
