import copy
import csv
import io
import json
import unittest
from reconcile import compare, IncompleteEvidence, REQUIRED_ZOHO

START,END=1000,2000

def card(card_id=17,alloc_id=801,status='approved',start=1100,sec=3600,code=None,configured=None,project=4):
    return {'id':card_id,'status':status,'employee_id':42,'start_dt_unix':start,
            'updated_at_unix':1500,'time_summary_v2':{'duration_secs':sec},
            'cost_allocations':[{'id':alloc_id,'duration_secs':sec,'org_project_id':project,
                                 'job_code_id':code,'org_project':{'cost_code_ids':configured if configured is not None else []},
                                 'is_sample_data':False}]}

def page(status,items,page=1,last=1,total=None):
    return {'meta':{'current_page':page,'last_page':last,'total':len(items) if total is None else total},'data':items}

def fixture():
    a=card()
    b=card(18,802,'processed',1200,5400,code=21,configured=[21])
    obj={'start_unix':START,'end_unix':END,'queried_statuses':['approved','processed','submitted','working'],
         'pages':{'approved':[page('approved',[a])],'processed':[page('processed',[b])],
                  'submitted':[page('submitted',[])],'working':[page('working',[])]}}
    return obj

def csv_of(workyard):
    rows=[]
    for status in ['approved','processed','submitted','working']:
        for pg in workyard['pages'][status]:
            for c in pg['data']:
                for a in c['cost_allocations']:
                    rows.append({'time_card_id':str(c['id']),'allocation_id':str(a['id']),
                                 'allocated_secs':str(a['duration_secs']),'time_card_status':c['status'],
                                 'time_card_start_dt_unix':str(c['start_dt_unix']),
                                 'workyard_project_id':str(a['org_project_id']) if a['org_project_id'] else '',
                                 'cost_code_id':str(a['job_code_id']) if a['job_code_id'] is not None else '',
                                 'time_card_updated_at_unix':str(c['updated_at_unix']),
                                 'synced_at':'2020-01-02 03:04:05'})
    out=io.StringIO(newline='');w=csv.DictWriter(out,fieldnames=REQUIRED_ZOHO);w.writeheader();w.writerows(rows)
    return out.getvalue()

class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.w=fixture();self.z=csv_of(self.w)
    def check(self,workyard=None,zoho=None,private_details=False):
        return compare(self.w if workyard is None else workyard,self.z if zoho is None else zoho,START,END,private_details=private_details)
    def test_valid_complete_exact(self):
        x=self.check();self.assertTrue(x['complete']);self.assertTrue(x['exact_match']);self.assertEqual(x['card_count'],2);self.assertEqual(x['statuses'],dict(approved=1,processed=1,submitted=0,working=0));self.assertEqual(x['direct_allocations'],2)
    def test_aggregate_default_no_employee_or_record_ids(self):
        x=self.check();self.assertNotIn('private_exception_ids',x);self.assertNotIn('employee',json.dumps(x))
    def test_private_details_only_when_explicit(self):
        self.assertIn('private_exception_ids',self.check(private_details=True))
    def test_configured_missing_code_categorized_review_not_violation(self):
        self.w['pages']['approved'][0]['data'][0]['cost_allocations'][0]['org_project']['cost_code_ids']=[9]
        x=self.check(workyard=self.w);self.assertEqual(x['code_review_candidates'],1);self.assertTrue(x['exact_match']);self.assertEqual(x['code_classifications']['configured_project_uncoded'],1)
    def test_empty_project_missing_code_not_exception(self):
        x=self.check();self.assertEqual(x['code_review_candidates'],0);self.assertEqual(x['code_classifications']['unconfigured_project_uncoded'],1)
    def test_field_mismatch_fail_result(self):
        z=self.z.replace(',processed,',',approved,');x=self.check(zoho=z);self.assertFalse(x['exact_match']);self.assertEqual(x['field_mismatches'],1)
    def test_missing_zoho_allocation(self):
        z=self.z.replace(next(line for line in self.z.splitlines() if ',802,' in line)+'\r\n','')
        x=self.check(zoho=z);self.assertEqual(x['missing_in_zoho'],1);self.assertFalse(x['exact_match'])
    def test_extra_zoho_allocation(self):
        z=self.z+'99,999,30,approved,1300,4,,1400,2020-01-02 03:04:05\r\n';x=self.check(zoho=z);self.assertEqual(x['missing_in_workyard'],1)
    def test_duplicate_zoho_allocation_fails_closed(self):
        z=self.z+self.z.splitlines()[1]+'\r\n'
        with self.assertRaisesRegex(IncompleteEvidence,'duplicate Zoho'):self.check(zoho=z)
    def test_missing_zoho_column_fails(self):
        z=self.z.replace('time_card_updated_at_unix,','')
        with self.assertRaises(IncompleteEvidence):self.check(zoho=z)
    def test_unknown_status_query_missing(self):
        self.w['queried_statuses'].remove('processed')
        with self.assertRaisesRegex(IncompleteEvidence,'four required'):self.check(workyard=self.w)
    def test_missing_processed_page(self):
        del self.w['pages']['processed']
        with self.assertRaisesRegex(IncompleteEvidence,'missing status'):self.check(workyard=self.w)
    def test_processed_status_not_approved(self):
        self.w['pages']['processed'][0]['data'][0]['status']='approved'
        with self.assertRaisesRegex(IncompleteEvidence,'status mismatch'):self.check(workyard=self.w)
    def test_workyard_page_count_missing(self):
        self.w['pages']['approved'][0]['meta']['last_page']=2
        with self.assertRaisesRegex(IncompleteEvidence,'unfetched page'):self.check(workyard=self.w)
    def test_real_pagination_across_two_pages(self):
        a=self.w['pages']['approved'][0]['data'][0]
        b=card(19,803,'approved',1300,1800,code=8,configured=[8])
        self.w['pages']['approved']=[
            page('approved',[a],page=1,last=2,total=2),
            page('approved',[b],page=2,last=2,total=2)]
        z=csv_of(self.w)
        x=self.check(workyard=self.w,zoho=z)
        self.assertTrue(x['exact_match']);self.assertEqual(x['statuses']['approved'],2)
        self.assertEqual(x['direct_allocations'],3)
    def test_missing_middle_page_never_succeeds(self):
        a=self.w['pages']['approved'][0]['data'][0]
        b=card(19,803,'approved',1300,1800,code=8,configured=[8])
        self.w['pages']['approved']=[
            page('approved',[a],page=1,last=3,total=2),
            page('approved',[b],page=3,last=3,total=2)]
        with self.assertRaisesRegex(IncompleteEvidence,'pagination gap'):self.check(workyard=self.w)
    def test_page_total_changed_between_requests_denied(self):
        a=self.w['pages']['approved'][0]['data'][0]
        b=card(19,803,'approved',1300,1800,code=8,configured=[8])
        self.w['pages']['approved']=[
            page('approved',[a],page=1,last=2,total=2),
            page('approved',[b],page=2,last=2,total=3)]
        with self.assertRaisesRegex(IncompleteEvidence,'inconsistent pagination meta'):self.check(workyard=self.w)
    def test_workyard_total_understates(self):
        self.w['pages']['approved'][0]['meta']['total']=0
        with self.assertRaisesRegex(IncompleteEvidence,'inconsistent total'):self.check(workyard=self.w)
    def test_wrong_period_record_fails(self):
        self.w['pages']['approved'][0]['data'][0]['start_dt_unix']=999
        with self.assertRaisesRegex(IncompleteEvidence,'outside local period'):self.check(workyard=self.w)
    def test_unreconciled_card_duration_fails(self):
        self.w['pages']['approved'][0]['data'][0]['time_summary_v2']['duration_secs']=3601
        with self.assertRaisesRegex(IncompleteEvidence,'duration does not reconcile'):self.check(workyard=self.w)
    def test_duplicate_workyard_card_fails(self):
        self.w['pages']['processed'][0]['data'][0]['id']=17
        with self.assertRaisesRegex(IncompleteEvidence,'duplicate card'):self.check(workyard=self.w)
    def test_duplicate_workyard_allocation_fails(self):
        self.w['pages']['processed'][0]['data'][0]['cost_allocations'][0]['id']=801
        with self.assertRaisesRegex(IncompleteEvidence,'duplicate allocation'):self.check(workyard=self.w)
    def test_sample_flag_fail_closed(self):
        self.w['pages']['approved'][0]['data'][0]['cost_allocations'][0]['is_sample_data']=True
        with self.assertRaisesRegex(IncompleteEvidence,'sample-data'):self.check(workyard=self.w)
    def test_unknown_project_code_config_fail(self):
        del self.w['pages']['approved'][0]['data'][0]['cost_allocations'][0]['org_project']['cost_code_ids']
        with self.assertRaisesRegex(IncompleteEvidence,'unknown cost code'):self.check(workyard=self.w)
    def test_missing_project_is_not_a_false_success(self):
        self.w['pages']['approved'][0]['data'][0]['cost_allocations'][0]['org_project_id']=None
        x=self.check(workyard=self.w);self.assertEqual(x['code_classifications'].get('missing_project'),1);self.assertFalse(x['exact_match'])
    def test_zoho_update_changed_detected(self):
        z=self.z.replace(',1500,2020',',1510,2020',1)
        x=self.check(zoho=z);self.assertFalse(x['exact_match']);self.assertEqual(x['field_mismatches'],1)
    def test_zoho_sync_empty_fails(self):
        z=self.z.replace('2020-01-02 03:04:05','')
        with self.assertRaisesRegex(IncompleteEvidence,'synced_at'):self.check(zoho=z)
    def test_zoho_sync_tz_unproven_caveat(self):
        self.assertIn('Zoho synced_at lacks timezone',self.check()['caveats'])
    def test_zoho_extra_column_malformed(self):
        z=self.z+self.z.splitlines()[1]+',EXTRA\r\n'
        with self.assertRaises(IncompleteEvidence):self.check(zoho=z)
    def test_dates_have_open_upper_bound(self):
        self.w['pages']['approved'][0]['data'][0]['start_dt_unix']=END
        with self.assertRaisesRegex(IncompleteEvidence,'outside local period'):self.check(workyard=self.w)
    def test_invalid_negative_seconds_fails(self):
        self.w['pages']['approved'][0]['data'][0]['cost_allocations'][0]['duration_secs']=-1
        with self.assertRaisesRegex(IncompleteEvidence,'invalid seconds'):self.check(workyard=self.w)

if __name__=='__main__':unittest.main()
