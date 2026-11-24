"""Make Arduino's required folder/file naming layout without duplicating maintained code."""
from pathlib import Path
import shutil
root=Path(__file__).resolve().parent
out=root/'build/esp32_caalc'; out.mkdir(parents=True,exist_ok=True)
shutil.copy2(root/'firmware/esp32_caalc/esp32_caalc.ino',out/'esp32_caalc.ino')
for name in ('caalc_core.h','round_constants.h'): shutil.copy2(root/'firmware/include'/name,out/name)
shutil.copytree(root/'vendor/ascon',out/'src/ascon',dirs_exist_ok=True)
print('Firmware package ready at',out)
print('Arduino IDE: open',out/'esp32_caalc.ino')
print('PlatformIO: open the project root; it uses platformio.ini and this generated package.')
