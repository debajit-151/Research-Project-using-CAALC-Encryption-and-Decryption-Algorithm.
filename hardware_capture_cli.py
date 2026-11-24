"""Terminal-only CAALC hardware capture for two ESP32 DevKit V1 boards."""
from __future__ import annotations

import argparse
import getpass
import json
import sys

import hardware_dashboard as hardware


class ConsoleProgress:
    def __init__(self):
        self.last_text = None

    def progress(self, _value, text=''):
        if text and text != self.last_text:
            print(f'[progress] {text}', flush=True)
            self.last_text = text


class ConsoleStatus:
    def info(self, text):
        print(f'[status] {text}', flush=True)


class ConsoleMetrics:
    def __init__(self):
        self.values = {}

    def metric(self, label, value):
        if self.values.get(label) != value:
            print(f'[metric] {label}: {value}', flush=True)
            self.values[label] = value


class NullChart:
    def line_chart(self, *_args, **_kwargs):
        pass


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sender-port', default='COM5' if sys.platform == 'win32' else '/dev/cu.usbserial-0001')
    parser.add_argument('--relay-port', default='COM6' if sys.platform == 'win32' else '/dev/cu.usbserial-5')
    parser.add_argument('--ssid', required=True, help='2.4 GHz Wi-Fi network name')
    parser.add_argument('--laptop-ip', default=hardware.discover_lan_ip())
    parser.add_argument('--udp-port', type=int, default=5005)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--algorithm', choices=('caalc', 'ascon'), default='caalc')
    parser.add_argument('--open-network', action='store_true',
                        help='Use an empty Wi-Fi password without prompting')
    args = parser.parse_args()
    if args.sender_port == args.relay_port:
        parser.error('sender and relay ports must be different')
    if not 5 <= args.seconds <= 60:
        parser.error('--seconds must be between 5 and 60')
    if not args.laptop_ip:
        parser.error('--laptop-ip is required when it cannot be detected')
    return args


def main():
    args = parse_args()
    password = '' if args.open_network else getpass.getpass(
        f'Wi-Fi password for {args.ssid!r} (input hidden): '
    )
    try:
        _audio, report = hardware.run_capture(
            args.sender_port, args.relay_port, args.ssid, password,
            args.laptop_ip, args.udp_port, args.seconds, args.algorithm,
            ConsoleProgress(), ConsoleStatus(), ConsoleMetrics(), NullChart(),
        )
        print('[complete] Authenticated audio saved successfully.')
        print(json.dumps(report, indent=2))
    finally:
        hardware.get_serial_registry().close_all()


if __name__ == '__main__':
    main()
