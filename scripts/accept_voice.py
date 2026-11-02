"""Explicit physical microphone + local-model WER run; never routine setup."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',type=Path,default=os.environ.get('LINXAI_VOICE_MODEL') or os.environ.get('LINXAI_WHISPER_MODEL'))
    parser.add_argument('--reference',default=os.environ.get('LINXAI_VOICE_REFERENCE'))
    parser.add_argument('--report',type=Path,default=Path('voice-acceptance.json'))
    args=parser.parse_args()
    model=args.model
    reference=args.reference
    if os.environ.get('LINXAI_TEST_HARDWARE')!='1' or not model or not reference:
        print('PENDING: hardware opt-in, existing local model and known spoken reference required')
        return 3
    from voice.client import listen
    from voice.pipeline import wer
    transcript=listen(model)
    result={'kind':'actual microphone/local-model run','transcript':transcript,'reference':reference,**wer(reference,transcript)}
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['wer']<=0.15 else 1


if __name__=='__main__':raise SystemExit(main())
