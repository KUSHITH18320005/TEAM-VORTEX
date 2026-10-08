const { z } = require("zod");
const crypto = require("crypto");

// Individual Log Event Ingress Schema
const singleLogSchema = z.object({
  eventId: z.string().optional().default(() => `evt_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`),
  timestamp: z.union([z.string(), z.date(), z.number()]).optional().transform((val) => {
    if (!val) return new Date().toISOString();
    if (val instanceof Date) return val.toISOString();
    if (typeof val === "number") return new Date(val).toISOString();
    const d = new Date(val);
    return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
  }),
  ip: z.string().optional(),
  sourceIp: z.string().optional(),
  category: z.string().min(1, "Category cannot be empty").default("general"),
  layer: z.string().optional().default("application"),
  source: z.string().optional().default("application-runtime"),
  endpoint: z.string().optional().default("/telemetry"),
  method: z.string().optional().default("DATA"),
  payload: z.union([z.record(z.any()), z.string()]).optional().transform((val) => {
    if (!val) return { body: {}, query: {}, params: {} };
    if (typeof val === "string") return { raw: val, body: {}, query: {}, params: {} };
    return val;
  }),
  details: z.record(z.any()).optional().default({}),
  dataset: z.string().optional(),
  campaign_id: z.string().optional(),
  campaignId: z.string().optional(),
  org_id: z.string().optional(),
  orgId: z.string().optional(),
  effect: z.any().optional(),
}).passthrough().transform((data) => {
  // Normalize sourceIp / ip
  const resolvedIp = data.sourceIp || data.ip || "127.0.0.1";
  const resolvedCampaign = data.campaign_id || data.campaignId || undefined;
  const resolvedOrg = data.org_id || data.orgId || undefined;
  
  return {
    eventId: data.eventId || `evt_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
    timestamp: data.timestamp,
    ip: resolvedIp,
    sourceIp: resolvedIp,
    category: data.category.toLowerCase().trim(),
    layer: (data.layer || "application").toLowerCase().trim(),
    source: data.source || "application-runtime",
    endpoint: data.endpoint || "/telemetry",
    method: (data.method || "DATA").toUpperCase(),
    payload: data.payload || { body: {}, query: {}, params: {} },
    details: data.details || {},
    dataset: data.dataset,
    campaign_id: resolvedCampaign,
    org_id: resolvedOrg,
    effect: data.effect,
  };
});

const batchLogSchema = z.union([
  z.array(singleLogSchema).min(1, "Batch array cannot be empty"),
  z.object({
    events: z.array(singleLogSchema).min(1, "Batch events array cannot be empty"),
  }).transform((obj) => obj.events),
  z.object({
    logs: z.array(singleLogSchema).min(1, "Batch logs array cannot be empty"),
  }).transform((obj) => obj.logs),
]);

/**
 * Validates a single event payload.
 * Returns { success: true, data: NormalizedLog } or { success: false, errors: Array }
 */
function validateSingleLog(payload) {
  const result = singleLogSchema.safeParse(payload);
  if (!result.success) {
    const formattedErrors = result.error.errors.map((e) => ({
      field: e.path.join("."),
      message: e.message,
      code: e.code,
    }));
    return { success: false, errors: formattedErrors };
  }
  return { success: true, data: result.data };
}

/**
 * Validates a batch payload.
 * Returns { success: true, data: Array<NormalizedLog> } or { success: false, errors: Array }
 */
function validateBatchLogs(payload) {
  const result = batchLogSchema.safeParse(payload);
  if (!result.success) {
    const formattedErrors = result.error.errors.map((e) => ({
      field: e.path.join("."),
      message: e.message,
      code: e.code,
    }));
    return { success: false, errors: formattedErrors };
  }
  return { success: true, data: result.data };
}

module.exports = {
  singleLogSchema,
  batchLogSchema,
  validateSingleLog,
  validateBatchLogs,
};
