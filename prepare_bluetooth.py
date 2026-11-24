"""Prepare distinct Arduino/PlatformIO packages for ESP32 A and ESP32 B."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent

def package(role: str, source: Path, name: str) -> Path:
    out = ROOT / 'build' / name
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, out / (name + '.ino'))
    for header in ('caalc_core.h', 'round_constants.h'):
        shutil.copy2(ROOT / 'firmware' / 'include' / header, out / header)
    shutil.copytree(ROOT / 'vendor' / 'ascon', out / 'src' / 'ascon', dirs_exist_ok=True)
    print(f'{role} sketch package ready: {out}')
    return out

package('ESP32 A Bluetooth audio sender', ROOT / 'firmware/esp32_bt_sender/esp32_bt_sender.ino', 'esp32_bt_sender')
package('ESP32 B Bluetooth-to-Wi-Fi relay', ROOT / 'firmware/esp32_wifi_relay/esp32_wifi_relay.ino', 'esp32_wifi_relay')
