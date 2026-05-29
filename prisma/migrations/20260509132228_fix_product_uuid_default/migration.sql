-- CreateTable
CREATE TABLE "merchants" (
    "token_number" VARCHAR(255) NOT NULL,
    "order_id" VARCHAR(255),
    "name" VARCHAR(255) NOT NULL,
    "merchant_name" VARCHAR(255),
    "email" VARCHAR(255) NOT NULL,
    "phone" VARCHAR(20) NOT NULL,
    "address" VARCHAR(500),
    "city" VARCHAR(100),
    "subdistrict" VARCHAR(100),
    "regency" VARCHAR(100),
    "province" VARCHAR(100),
    "postal_code" VARCHAR(10),
    "package" VARCHAR(50),
    "amount" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "status" VARCHAR(50) NOT NULL DEFAULT 'pending',
    "payment_method" VARCHAR(50),
    "payment_url" VARCHAR(500),
    "payment_status" VARCHAR(50) NOT NULL DEFAULT 'pending',
    "midtrans_order_id" VARCHAR(255),
    "paid_at" TIMESTAMPTZ(6),
    "register_date" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status_active" BOOLEAN NOT NULL DEFAULT false,
    "device_id" VARCHAR(255),
    "device_name" VARCHAR(255),
    "device_type" VARCHAR(255),
    "referral_code" VARCHAR(255),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "merchants_pkey" PRIMARY KEY ("token_number")
);

-- CreateTable
CREATE TABLE "product" (
    "id" UUID NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "slug" VARCHAR(255) NOT NULL,
    "price" DECIMAL(12,2) NOT NULL,
    "photo_url" VARCHAR(500),
    "description" TEXT,
    "status" VARCHAR(50) NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "merchants_order_id_key" ON "merchants"("order_id");

-- CreateIndex
CREATE UNIQUE INDEX "product_name_key" ON "product"("name");

-- CreateIndex
CREATE UNIQUE INDEX "product_slug_key" ON "product"("slug");

-- CreateIndex
CREATE INDEX "product_slug_idx" ON "product"("slug");

-- CreateIndex
CREATE INDEX "product_status_idx" ON "product"("status");
