#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:=/tmp}"
export WRANGLER_SEND_METRICS=false
conf="research/durable_dispatch/wrangler.lab.toml"
schema="research/durable_dispatch/schema.sql"
fixtures="research/durable_dispatch/fixtures.sql"
persist="$RUNNER_TEMP/uag-durable-dispatch-db"
mkdir -p "$persist"
# Uses a deliberately empty/disposable local DB and cannot deploy remotely.
npx wrangler d1 execute DB --local --config "$conf" --persist-to "$persist" --file "$schema" --yes >/dev/null
npx wrangler d1 execute DB --local --config "$conf" --persist-to "$persist" --file "$fixtures" --yes >/dev/null
npx wrangler dev --local --ip 127.0.0.1 --port 18921 --test-scheduled --config "$conf" --persist-to "$persist" >"$RUNNER_TEMP/uag-durable-lab.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
ready=0
for _ in $(seq 1 70); do
  if curl -fsS --max-time 1 http://127.0.0.1:18921/health -o "$RUNNER_TEMP/dispatch-health.json" >/dev/null 2>&1; then ready=1;break;fi
  if ! kill -0 "$pid" 2>/dev/null; then tail -n 90 "$RUNNER_TEMP/uag-durable-lab.log";exit 1;fi
  sleep 0.5
done
test "$ready" -eq 1
python - "$RUNNER_TEMP/dispatch-health.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))=={'service':'uag-durable-dispatch-research','effects':'none','external_connections':'none'}
PY
for path in jobs owner/activate status v1/execute; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -X POST "http://127.0.0.1:18921/$path" -d '{}')
  test "$c" = 404
done
# Actual in-process local workerd scheduled event, invoked twice for same slot.
ts=$(node -e 'process.stdout.write(String(Math.floor(Date.now()/3600000)*3600000))')
printf '{"cron":"0 * * * *","scheduled_time":%s}' "$ts" >"$RUNNER_TEMP/uag-scheduled.json"
for i in 1 2; do
  curl --fail-with-body --max-time 30 -sS -X POST \
    'http://127.0.0.1:18921/cdn-cgi/local/explorer/api/local/scheduled?worker=uag-durable-dispatch-lab' \
    -H 'content-type: application/json' --data-binary @"$RUNNER_TEMP/uag-scheduled.json" \
    -o "$RUNNER_TEMP/uag-scheduled-response-$i.json"
done
npx wrangler d1 execute DB --local --config "$conf" --persist-to "$persist" --command "SELECT slot_ms,dispatch_type FROM dispatch_ticks" --json >"$RUNNER_TEMP/uag-ticks.json"
npx wrangler d1 execute DB --local --config "$conf" --persist-to "$persist" --command "SELECT job_id,route,state,attempts,result_sha256,last_error FROM dispatch_jobs ORDER BY job_id" --json >"$RUNNER_TEMP/uag-jobs.json"
npx wrangler d1 execute DB --local --config "$conf" --persist-to "$persist" --command "SELECT kind,COUNT(*) AS n FROM dispatch_events GROUP BY kind ORDER BY kind" --json >"$RUNNER_TEMP/uag-events.json"
python - "$RUNNER_TEMP/uag-ticks.json" "$RUNNER_TEMP/uag-jobs.json" "$RUNNER_TEMP/uag-events.json" <<'PY'
import json,sys
r=[json.load(open(x))[0]['results'] for x in sys.argv[1:]]
ticks,jobs,events=r
assert len(ticks)==1,ticks
assert ticks[0]['dispatch_type']=='synthetic_only'
d={x['job_id']:x for x in jobs}
assert len(d)==6,d
assert d['readok']['state']=='succeeded' and d['readok']['attempts']==1,d['readok']
assert d['recovered']['state']=='succeeded' and d['recovered']['attempts']==2,d['recovered']
assert d['retryonce']['state']=='queued' and d['retryonce']['attempts']==1,d['retryonce']
assert d['retryonce']['last_error']=='injected_retryable_read_failure',d['retryonce']
for job_id in ('writeheld','deviceheld','connectorheld'):
 assert d[job_id]['state']=='queued' and d[job_id]['attempts']==0,d[job_id]
for job_id in ('readok','recovered'):
 assert len(d[job_id]['result_sha256'])==64,d[job_id]
counts={e['kind']:e['n'] for e in events}
assert counts=={'claimed':3,'retry_queued':1,'succeeded':2},counts
print('UAG_REAL_WORKERD_D1_DURABLE_MULTIJOB_LIFECYCLE_VERIFIED')
print('UAG_EFFECT_LANES_REMAIN_DISABLED_3_OF_3')
PY
