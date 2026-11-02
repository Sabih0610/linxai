"""Bounded PCM/VAD/transcription contracts with lazy hardware/model imports."""
import io
from pathlib import Path
import queue
import re
import time
import wave

SAMPLE_RATE=16000
FRAME_BYTES=960


def select_speech(frames,vad,max_frames=500):
    selected=[];speech=False;quiet=0
    for index,frame in enumerate(frames):
        if index>=max_frames:break
        if not isinstance(frame,bytes) or len(frame)!=FRAME_BYTES:raise ValueError('Expected 30ms mono 16-bit PCM frame')
        voiced=vad.is_speech(frame,SAMPLE_RATE)
        if voiced:speech=True;quiet=0
        elif speech:quiet+=1
        if speech:selected.append(frame)
        if speech and quiet>=20:break
    if not speech:raise ValueError('No speech detected; no operation proposed')
    return b''.join(selected)


def capture(duration=10):
    if type(duration) is not int or not 1<=duration<=15:raise ValueError('Capture duration 1–15 seconds required')
    import sounddevice as sd
    import webrtcvad
    incoming=queue.Queue(maxsize=8);dropped=[0]
    def callback(data,frames,time_info,status):
        if status:dropped[0]+=1
        try:incoming.put_nowait(bytes(data))
        except queue.Full:dropped[0]+=1
    deadline=time.monotonic()+duration
    def frames():
        while time.monotonic()<deadline:
            try:yield incoming.get(timeout=min(0.1,max(0.001,deadline-time.monotonic())))
            except queue.Empty:continue
    with sd.RawInputStream(samplerate=SAMPLE_RATE,blocksize=480,channels=1,dtype='int16',callback=callback):
        pcm=select_speech(frames(),webrtcvad.Vad(2),max_frames=duration*1000//30)
    if dropped[0]:raise RuntimeError('Audio overflow; retry rather than transcribe incomplete input')
    return pcm


def transcribe(pcm,model_path):
    if not isinstance(pcm,bytes) or not 0<len(pcm)<=480000 or len(pcm)%2:raise ValueError('Bounded 16-bit PCM required')
    path=Path(model_path)
    if not path.is_absolute() or not path.is_dir():raise ValueError('Explicit existing local Whisper model directory required; downloads disabled')
    from faster_whisper import WhisperModel
    model=WhisperModel(str(path),device='cpu',compute_type='int8',cpu_threads=2,num_workers=1,local_files_only=True)
    data=io.BytesIO()
    with wave.open(data,'wb') as stream:
        stream.setnchannels(1);stream.setsampwidth(2);stream.setframerate(SAMPLE_RATE);stream.writeframes(pcm)
    data.seek(0)
    segments,info=model.transcribe(data,beam_size=1,language='en',vad_filter=False,condition_on_previous_text=False)
    text=''
    for index,segment in enumerate(segments):
        if index>=128:raise ValueError('Transcript segment budget exceeded')
        text+=segment.text+' '
        if len(text.encode())>8192:raise ValueError('Transcript exceeds input budget')
    text=' '.join(text.split())
    if not text:raise ValueError('Empty transcript; no operation proposed')
    return text


def wer(reference,hypothesis):
    def words(value):
        if not isinstance(value,str) or len(value)>16384:raise ValueError('Bounded text required')
        result=re.findall(r"[\w.+/-]+",value.casefold())
        if len(result)>1024:raise ValueError('WER word budget exceeded')
        return result
    expected,actual=words(reference),words(hypothesis)
    if not expected:raise ValueError('Nonempty reference required')
    previous=list(range(len(actual)+1))
    for index,word in enumerate(expected,1):
        current=[index]
        for j,other in enumerate(actual,1):current.append(min(previous[j]+1,current[j-1]+1,previous[j-1]+(word!=other)))
        previous=current
    return {'errors':previous[-1],'reference_words':len(expected),'wer':previous[-1]/len(expected)}
