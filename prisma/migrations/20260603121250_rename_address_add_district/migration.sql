-- Migration: Rename address fields to match new structure
-- address → street_address
-- remove regency
-- add district
-- reorder: province, city, district, subdistrict, postal_code, street_address

-- Step 1: Rename column address → street_address
ALTER TABLE merchants RENAME COLUMN "address" TO "street_address";

-- Step 2: Add new column district
ALTER TABLE merchants ADD COLUMN "district" VARCHAR(100);

-- Step 3: Drop regency column
ALTER TABLE merchants DROP COLUMN IF EXISTS "regency";
