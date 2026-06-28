import { Pool } from 'pg';
import dotenv from 'dotenv';
import path from 'path';

// Load .env from project root
dotenv.config({ path: path.join(process.cwd(), '.env') });

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 10000
});

async function main() {
    try {
        console.log("👱‍♀️ Ponytail Mode: Mendownload data wilayah se-Indonesia...");
        
        // Fetch data
        const [wilayahRes, kodeposRes] = await Promise.all([
            fetch('https://raw.githubusercontent.com/cahyadsn/wilayah/master/db/wilayah.sql').then(r => r.text()),
            fetch('https://raw.githubusercontent.com/cahyadsn/wilayah_kodepos/main/db/wilayah_kodepos.sql').then(r => r.text())
        ]);

        console.log("Data berhasil didownload, memproses...");

        // Parse wilayah
        const wilayahRegex = /\('([0-9\.]+)',\s*'([^']+)'\)/g;
        let match;
        
        const provinces: any[] = [];
        const regencies: any[] = [];
        const districts: any[] = [];
        const villagesMap = new Map<string, { id: string, district_id: string, name: string, postal_code: string | null }>();

        while ((match = wilayahRegex.exec(wilayahRes)) !== null) {
            const kode = match[1];
            const nama = match[2];

            if (kode.length === 2) {
                provinces.push({ id: kode, name: nama });
            } else if (kode.length === 5) { // XX.XX
                regencies.push({ id: kode, province_id: kode.substring(0, 2), name: nama });
            } else if (kode.length === 8) { // XX.XX.XX
                districts.push({ id: kode, regency_id: kode.substring(0, 5), name: nama });
            } else if (kode.length === 13) { // XX.XX.XX.XXXX
                villagesMap.set(kode, {
                    id: kode,
                    district_id: kode.substring(0, 8),
                    name: nama,
                    postal_code: null
                });
            }
        }

        // Parse kodepos
        const kodeposRegex = /\('([0-9\.]+)',\s*'([0-9]+)'\)/g;
        while ((match = kodeposRegex.exec(kodeposRes)) !== null) {
            const kode = match[1];
            const kodepos = match[2];
            const village = villagesMap.get(kode);
            if (village) {
                village.postal_code = kodepos;
            }
        }

        const villages = Array.from(villagesMap.values());
        
        console.log(`Berhasil mem-parsing:
- ${provinces.length} Provinsi
- ${regencies.length} Kota/Kab
- ${districts.length} Kecamatan
- ${villages.length} Kelurahan`);

        console.log("Mulai insert ke database (tunggu beberapa saat)...");

        // Helper function for bulk insert
        const bulkInsert = async (tableName: string, columns: string[], data: any[]) => {
            // Delete existing to prevent duplicate errors
            await pool.query(`TRUNCATE TABLE ${tableName} CASCADE`);
            
            // Chunking to avoid parameter limits (PostgreSQL max parameters is 65535)
            const chunkSize = 2000;
            for (let i = 0; i < data.length; i += chunkSize) {
                const chunk = data.slice(i, i + chunkSize);
                
                let valueIndex = 1;
                const values = [];
                const placeholders = [];
                
                for (const row of chunk) {
                    const rowPlaceholders = [];
                    for (const col of columns) {
                        values.push(row[col]);
                        rowPlaceholders.push(`$${valueIndex++}`);
                    }
                    placeholders.push(`(${rowPlaceholders.join(', ')})`);
                }
                
                const query = `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES ${placeholders.join(', ')}`;
                await pool.query(query, values);
            }
        };

        await bulkInsert('provinces', ['id', 'name'], provinces);
        console.log("✅ Provinces inserted");
        
        await bulkInsert('regencies', ['id', 'province_id', 'name'], regencies);
        console.log("✅ Regencies inserted");
        
        await bulkInsert('districts', ['id', 'regency_id', 'name'], districts);
        console.log("✅ Districts inserted");
        
        await bulkInsert('villages', ['id', 'district_id', 'name', 'postal_code'], villages);
        console.log("✅ Villages inserted (Ini paling lama, santai aja)");

        console.log("🎉 SELESAI! Semua data wilayah Indonesia beserta kodepos berhasil dimasukkan ke PostgreSQL.");

    } catch (err) {
        console.error("❌ Terjadi kesalahan:", err);
    } finally {
        await pool.end();
    }
}

main();
