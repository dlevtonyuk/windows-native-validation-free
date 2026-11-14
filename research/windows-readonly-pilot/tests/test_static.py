from pathlib import Path
import re,unittest,sqlite3,json
P=Path(__file__).resolve().parent.parent
class StaticSafeguards(unittest.TestCase):
    def test_readonly_windows_collector_has_no_network(self):
        s=(P/'windows'/'Collect-ReadOnlyAggregate.ps1').read_text()
        for forbidden in ['Invoke-WebRequest','Invoke-RestMethod','Start-Process','Remove-Item','Stop-Process','Register-ScheduledTask','Get-CimInstance','Get-WmiObject']:
            self.assertNotIn(forbidden,s)
        self.assertIn('GetSystemTimes',s)
        self.assertIn('GlobalMemoryStatusEx',s)
    def test_collector_no_process_details(self):
        s=(P/'windows'/'Collect-ReadOnlyAggregate.ps1').read_text()
        for forbidden in ['ProcessName','Get-Process','MainWindowTitle','WorkingSet64','CommandLine']:
            self.assertNotIn(forbidden,s)
    def test_sender_is_outbound_only_hard_domain(self):
        s=(P/'windows'/'Send-ReadOnlyAggregate-NOT-RUN.ps1').read_text()
        self.assertIn('cwfr-windows-telemetry-staging',s)
        self.assertIn('Invoke-WebRequest',s)
        self.assertNotIn('Invoke-Expression',s)
        self.assertNotIn('Register-ScheduledTask',s)
    def test_bootstrap_no_scheduler(self):
        s=(P/'windows'/'Prepare-LocalEnrollment-NOT-RUN.ps1').read_text()
        self.assertIn('ProtectedData',s)
        self.assertIn('CurrentUser',s)
        self.assertNotIn('Register-ScheduledTask',s)
        self.assertIn("endpoint=''",s)
    def test_schema_defaults_to_zero_active_devices(self):
        c=sqlite3.connect(':memory:')
        c.executescript((P/'cloud'/'schema.sql').read_text())
        self.assertEqual(c.execute('SELECT count(*) FROM device_registry').fetchone()[0],0)
        self.assertEqual(c.execute('SELECT count(*) FROM telemetry_readings').fetchone()[0],0)
    def test_schema_privacy(self):
        sql=(P/'cloud'/'schema.sql').read_text().lower()
        for forbidden in ['user_name', 'process_name','browser_history','command_line','filename','hostname']:
            self.assertNotIn(forbidden,sql)
    def test_worker_has_no_enrollment_or_commands(self):
        code=(P/'cloud'/'worker.mjs').read_text()
        self.assertIn("'/v1/telemetry'",code)
        self.assertNotIn("'/v1/enroll'",code)
        self.assertNotIn("'/v1/jobs'",code)
        self.assertNotIn('eval(',code)
        self.assertNotIn('new Function',code)
if __name__=='__main__':unittest.main()