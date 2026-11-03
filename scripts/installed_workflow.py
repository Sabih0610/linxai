"""Foreign-cwd installed-wheel workflow; invoke with the candidate Python -I."""
import argparse
import json
import os
from pathlib import Path
import threading
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True,type=Path)
    root=parser.parse_args().root
    from operations.agent import Agent,AgentClient,serve
    from operations.workflows import WorkflowSystem
    from operations.service import LocalPolicy,OperationService
    from operations.registry import ActionRegistry
    from operations.audit import JsonlAudit
    import operations
    import sys
    assert Path(operations.__file__).is_relative_to(Path(sys.prefix))
    workspace=root/'workspace';workspace.mkdir(mode=0o700)
    state=root/'state'
    agent=Agent(state,str(workspace));stop=threading.Event();errors=[]
    def server():
        try:serve(agent,state/'agent.sock',stop)
        except Exception as exc:errors.append(str(exc))
    thread=threading.Thread(target=server,daemon=True);thread.start()
    try:
        client=AgentClient(state/'agent.sock');deadline=time.monotonic()+5
        while not (state/'agent.sock').exists() and time.monotonic()<deadline:time.sleep(.02)
        row=client.call('preview',text='show memory usage')
        client.call('confirm',id=row['id'],digest=row['digest'])
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            result=client.call('job',id=row['id'])
            if result['state'] in {'succeeded','failed','unknown'}:break
            time.sleep(.02)
        assert result['state']=='succeeded',result
        assert result['operation_id']==result['result']['operation_id']
        # No credentials/model/device: actual installed typed stdlib recipe.
        service=OperationService(ActionRegistry(str(workspace),actor_uid=os.getuid()),WorkflowSystem(),LocalPolicy(os.getuid()),JsonlAudit(root/'audit.jsonl'))
        project=service.run({'action':'project.scaffold','parameters':{'path':'demo'}})
        assert project.status=='succeeded' and project.verified,project
        print(json.dumps({'agent_job':result['id'],'operation':result['operation_id'],'project_operation':project.operation_id,'source':'installed wheel','errors':errors}))
    finally:
        stop.set();thread.join(5)
    if errors or thread.is_alive():raise RuntimeError('Agent lifecycle failed: '+str(errors))


if __name__=='__main__':main()
