"""Isolated voice capture/decoder, supervised by the unprivileged caller."""
import argparse
import json
from operations.supervised import SupervisedLinuxAdapter


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',required=True)
    parser.add_argument('--duration',type=int,default=10)
    args=parser.parse_args(argv)
    if not SupervisedLinuxAdapter().resolve_identity().ordinary():raise PermissionError('Voice input requires ordinary account')
    from .pipeline import capture,transcribe
    text=transcribe(capture(args.duration),args.model)
    print(json.dumps({'text':text,'authorization':'none; preview/confirmation and OS policy still required'}))


if __name__=='__main__':main()
