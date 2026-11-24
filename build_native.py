"""Build portable sources with GCC/Clang; Windows: install MSYS2 UCRT64 GCC."""
import os,sys,subprocess,json
from pathlib import Path
from main import ROOT,RC
if __name__=='__main__':
    build=ROOT/'build'; build.mkdir(exist_ok=True)
    suffix='.dll' if os.name=='nt' else ('.dylib' if sys.platform=='darwin' else '.so')
    flags=['-O2','-shared']+([] if os.name=='nt' else ['-fPIC'])
    cmds=[['g++',*flags,'-std=c++11',str(ROOT/'native/native.cpp'),'-o',str(build/('libcaalc'+suffix))],['gcc',*flags,'-I'+str(ROOT/'vendor/ascon'),*[str(p) for p in sorted((ROOT/'vendor/ascon').glob('*.c'))],'-o',str(build/('libascon'+suffix))]]
    for cmd in cmds: print(' '.join(cmd)); subprocess.run(cmd,check=True)
    # Keep the recorded commands portable instead of embedding this machine's
    # absolute checkout path in a tracked result artifact.
    portable=[[arg.replace(str(ROOT),'.') for arg in cmd] for cmd in cmds]
    (ROOT/'results/build_commands.json').write_text(json.dumps(portable,indent=2)+'\n')
