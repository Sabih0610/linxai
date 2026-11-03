"""Bounded ordinary-user read/audit soak, not full-system or kernel stress evidence."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds',type=int,default=30)
    parser.add_argument('--interval',type=float,default=.5)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args(argv)
    if not 1<=args.seconds<=86400 or not .25<=args.interval<=60:parser.error('Duration 1..86400 seconds, interval .25..60 seconds required')
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy,OperationService
    from operations.workflows import WorkflowSystem
    identity=WorkflowSystem().resolve_identity()
    if not identity.ordinary():raise PermissionError('Ordinary Linux account required')
    start=time.monotonic();passed=failed=0;errors=[];interrupted=False
    with tempfile.TemporaryDirectory(prefix='.linxai-soak-',dir=Path.home()) as directory:
        service=OperationService(ActionRegistry(actor_uid=identity.uid),WorkflowSystem(),LocalPolicy(identity.uid),JsonlAudit(Path(directory)/'audit.jsonl'))
        try:
            while time.monotonic()-start<args.seconds:
                action='memory.usage' if (passed+failed)%2==0 else 'disk.usage'
                result=service.run({'action':action,'parameters':{}})
                if result.status=='succeeded' and result.verified:passed+=1
                else:
                    failed+=1;errors.append(asdict(result));errors=errors[-32:]
                if failed>=100:break
                time.sleep(min(args.interval,max(0,args.seconds-(time.monotonic()-start))))
        except KeyboardInterrupt:interrupted=True
        retained=sum(path.stat().st_size for path in Path(directory).iterdir() if path.is_file())
    elapsed=time.monotonic()-start
    result={'schema':1,'scope':'actual ordinary-user disk/memory operations and bounded audit only',
            'requested_seconds':args.seconds,'elapsed_seconds':elapsed,'passed':passed,'failed':failed,
            'completed':not interrupted and elapsed>=args.seconds,'interrupted':interrupted,
            'retained_audit_bytes':retained,'last_errors':errors,'full_24_hour_release_stress':'NOT DEMONSTRATED by this limited workload'}
    args.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
    return 0 if result['completed'] and passed>0 and failed==0 else 1


if __name__=='__main__':raise SystemExit(main())
