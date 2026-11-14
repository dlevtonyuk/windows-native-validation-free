-- Only disposable, invented IDs and simulated operations.
INSERT INTO dispatch_jobs(job_id,route,operation,due_ms,state,max_attempts) VALUES
 ('readok','cloud_readonly_mock','observe_ready',1,'queued',2),
 ('retryonce','cloud_readonly_mock','fail_first',1,'queued',2),
 ('recovered','cloud_readonly_mock','observe_ready',1,'queued',2),
 ('exhausted','cloud_readonly_mock','observe_ready',1,'queued',2),
 ('deviceheld','device_local','device_probe',1,'queued',2),
 ('connectorheld','connector_readonly','connector_probe',1,'queued',2),
 ('writeheld','owner_guarded_write','effect_probe',1,'queued',2);
UPDATE dispatch_jobs SET attempts=1,state='running',lease_until_ms=1,last_transition_ms=1 WHERE job_id='recovered';
UPDATE dispatch_jobs SET attempts=1,state='running',lease_until_ms=1,last_transition_ms=1 WHERE job_id='exhausted';
UPDATE dispatch_jobs SET state='queued',lease_until_ms=NULL,last_error='injected_prior_retryable_failure',last_transition_ms=2 WHERE job_id='exhausted';
UPDATE dispatch_jobs SET attempts=2,state='running',lease_until_ms=1,last_transition_ms=3 WHERE job_id='exhausted';
