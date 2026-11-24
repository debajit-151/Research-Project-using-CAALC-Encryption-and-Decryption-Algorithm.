"""Fresh session provisioning and receiver, with no source edits required."""
import argparse,json,os,socket,time
from pathlib import Path
import main

def read_pq_session(path):
    """Load a key/session pair emitted by the local authenticated demo."""
    try:
        data=json.loads(Path(path).read_text())
        if data.get('format')!='CAALC-PQS1-SESSION' or data.get('version')!=1:
            raise ValueError('Not a supported authenticated session file')
        algorithm=data['suite']
        if algorithm not in ('caalc','ascon'):
            raise ValueError('Unsupported session cipher suite')
        key=bytes.fromhex(data['traffic_key_hex']); sid=bytes.fromhex(data['session_id_hex'])
        if len(key)!=16 or len(sid)!=8:
            raise ValueError('Invalid authenticated session key or ID length')
        return key,sid,algorithm
    except (KeyError,TypeError,json.JSONDecodeError) as exc:
        raise ValueError('Malformed authenticated session file') from exc

def provision(port,key,sid,ssid,password,host,udp_port,mode,algorithm='caalc'):
    import serial
    for v in (ssid,password,host):
        if any(c.isspace() for c in v): raise ValueError('This compact firmware config requires SSID/password without whitespace')
    with serial.Serial(port,921600,timeout=.1) as ser:
        time.sleep(2); ser.reset_input_buffer()
        suite=algorithm.upper()
        if suite not in ('CAALC','ASCON'): raise ValueError('Algorithm must be caalc or ascon')
        ser.write(f'CFG {key.hex()} {sid.hex()} {ssid or "-"} {password or "-"} {host} {udp_port} {mode} {suite}\n'.encode()); ser.flush()
        start=time.monotonic()
        while time.monotonic()-start<25:
            line=ser.readline().decode(errors='replace').strip()
            if line: print(line)
            if line=='READY': return
            if line.startswith('ERR'): raise RuntimeError(line)
        raise TimeoutError('Board did not acknowledge provisioning; check COM port, baud and board firmware')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--serial',required=True);p.add_argument('--mode',choices=['USB','MIC'],default='USB');p.add_argument('--algorithm',choices=['caalc','ascon']);p.add_argument('--wav');p.add_argument('--seconds',type=int,default=10);p.add_argument('--out',default='results/hardware.wav');p.add_argument('--ssid',default='');p.add_argument('--host',default='');p.add_argument('--port',type=int,default=5005);p.add_argument('--play',action='store_true');p.add_argument('--key',help='Optional ML-KEM-generated session.key, use only for a fresh session');p.add_argument('--session-file',help='Use key, session ID and cipher suite from pq_session.py --write-session')
    a=p.parse_args(); import getpass
    if a.key and a.session_file: p.error('Use only one of --key or --session-file')
    if a.session_file:
        key,sid,session_algorithm=read_pq_session(a.session_file)
        if a.algorithm and a.algorithm!=session_algorithm: p.error('--algorithm must match the authenticated session file')
        algorithm=session_algorithm
    else:
        key=main.key_read(a.key) if a.key else os.urandom(16); sid=os.urandom(8)
        algorithm=a.algorithm or 'caalc'
    dest=Path(a.out); dest.parent.mkdir(parents=True,exist_ok=True)
    config=dest.with_suffix('.config.json'); cfg={'ssid':a.ssid or '-','password':'-','host':a.host or '127.0.0.1','mode':a.mode,'algorithm':algorithm}
    # USB keeps the port open, avoiding a second reset and lost provisioning.
    if a.mode=='USB':
        if not a.wav: p.error('--wav is required for USB input')
        main.write_json(config,cfg)
        print(main.receive(key,sid,a.out,a.seconds,a.port,a.serial,a.play,algorithm=algorithm,session_config=config,serial_audio=a.wav))
    else:
        if not a.host or not a.ssid: p.error('MIC requires --host laptopIPv4 and --ssid')
        password=getpass.getpass('Wi-Fi password (blank for open network): ')
        # Receiver runs before provisioning so initial sequence frames are not missed.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            result=pool.submit(main.receive,key,sid,a.out,a.seconds+25,a.port,None,a.play,algorithm=algorithm)
            time.sleep(.1); provision(a.serial,key,sid,a.ssid,password,a.host,a.port,'MIC',algorithm); print(result.result())
    # Key intentionally not printed or saved. Optional ML-KEM input stays in its user-created file.
