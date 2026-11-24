from pathlib import Path
import shutil
root=Path(__file__).resolve().parent; out=root/'build/esp32_benchmark'; out.mkdir(parents=True,exist_ok=True)
shutil.copy2(root/'firmware/benchmark/esp32_benchmark.ino',out/'esp32_benchmark.ino')
for name in ('caalc_core.h','round_constants.h'): shutil.copy2(root/'firmware/include'/name,out/name)
shutil.copytree(root/'vendor/ascon',out/'src/ascon',dirs_exist_ok=True)
print('Benchmark sketch ready at',out/'esp32_benchmark.ino','for Arduino IDE; use the sender board/core settings.')
