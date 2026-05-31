-- CreateTable
CREATE TABLE "notifications" (
    "id" UUID NOT NULL,
    "title" VARCHAR(255) NOT NULL,
    "body" TEXT NOT NULL,
    "type" VARCHAR(50) NOT NULL DEFAULT 'info',
    "target_type" VARCHAR(50) NOT NULL DEFAULT 'broadcast',
    "token_number" VARCHAR(255),
    "status" VARCHAR(50) NOT NULL DEFAULT 'scheduled',
    "scheduled_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_reads" (
    "id" UUID NOT NULL,
    "notification_id" UUID NOT NULL,
    "token_number" VARCHAR(255) NOT NULL,
    "read_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_reads_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "notifications_type_idx" ON "notifications"("type");

-- CreateIndex
CREATE INDEX "notifications_target_type_idx" ON "notifications"("target_type");

-- CreateIndex
CREATE INDEX "notifications_token_number_idx" ON "notifications"("token_number");

-- CreateIndex
CREATE INDEX "notifications_status_idx" ON "notifications"("status");

-- CreateIndex
CREATE INDEX "notifications_scheduled_at_idx" ON "notifications"("scheduled_at");

-- CreateIndex
CREATE INDEX "notification_reads_token_number_idx" ON "notification_reads"("token_number");

-- CreateIndex
CREATE UNIQUE INDEX "notification_reads_notification_id_token_number_key" ON "notification_reads"("notification_id", "token_number");
