"""Run only exact named final-quorum safety tests in a disposable test environment.
No provider access, network calls, business effects or source modifications.
"""
import ast
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parent
SRC=ROOT/'test_final_quorum_fence.py'
node=ast.parse(SRC.read_text(encoding='utf8'))
tests=[f.name for c in node.body if isinstance(c,ast.ClassDef) and c.name=='FinalQuorumTests' for f in c.body if isinstance(f,ast.FunctionDef) and f.name.startswith('test_')]
assert len(tests)==12 and len(set(tests))==12, 'Unexpected test surface'
manifest=json.loads((ROOT/'MANIFEST.json').read_text(encoding='utf8'))
for name,digest in manifest.items():
    path=ROOT/name
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest, 'Source hash mismatch: '+name
print('SOURCE_SHA256_VERIFIED',len(manifest),flush=True)
r=subprocess.run([sys.executable,'-W','ignore::ResourceWarning','-m','unittest','-v',*('test_final_quorum_fence.FinalQuorumTests.'+t for t in tests)],cwd=ROOT,timeout=120,check=False)
if r.returncode:sys.exit(r.returncode)
print('FINAL_QUORUM_PORTABLE_12_12_PASSED',flush=True)
