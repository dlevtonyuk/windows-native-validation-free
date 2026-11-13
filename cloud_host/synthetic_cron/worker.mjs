// Independently scheduled, synthetic-only Cloudflare research candidate.
// No credentials, business adapters, external fetch calls, or HTTP write routes.
const CRON = '0 * * * *';
const SLOT_MS = 60 * 60 * 1000;
const MAX_DELAY_MS = 90 * 60 * 1000;
const response = (status, data) => new Response(JSON.stringify(data), {
  status, headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  }
});

export async function recordSyntheticSlot(controller, env, nowMs=Date.now()) {
  if (!controller || controller.cron !== CRON) throw Error('unapproved_schedule');
  if (!Number.isSafeInteger(controller.scheduledTime) || !Number.isFinite(nowMs))
    throw Error('invalid_clock');
  if (controller.scheduledTime > nowMs + 120000 || nowMs - controller.scheduledTime > MAX_DELAY_MS)
    throw Error('scheduled_time_out_of_bounds');
  if (!env || !env.DB || typeof env.DB.prepare !== 'function')
    throw Error('database_not_bound');
  const slotMs = Math.floor(controller.scheduledTime / SLOT_MS) * SLOT_MS;
  if (slotMs <= 0) throw Error('invalid_slot');
  const statement = env.DB.prepare(
    "INSERT INTO synthetic_cron_receipts(slot_ms, kind, scheduled_at_ms) " +
    "VALUES (?, 'synthetic_heartbeat', ?) ON CONFLICT(slot_ms) DO NOTHING"
  );
  const result = await statement.bind(slotMs, controller.scheduledTime).run();
  if (result?.success !== true) throw Error('receipt_write_not_confirmed');
  // Receipt exists at most once per hour; no operational capabilities exist.
  return {slot_ms:slotMs, inserted:result.meta?.changes === 1};
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health' && !url.search)
      return response(200, {service:'uag-synthetic-cron', status:'no_business_capabilities'});
    return response(404, {error:'unsupported_operation'});
  },
  async scheduled(controller, env) {
    return recordSyntheticSlot(controller, env);
  }
};
