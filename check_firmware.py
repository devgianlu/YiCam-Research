import sys

from lib.api import Api


def main():
    api = Api()
    api.login(sys.argv[1], sys.argv[2])

    # old version for testing: 9.0.35.00_202111291330

    for device in api.devices_list():
        upgrade_bytes = api.vmanager_download_upgrade(device['uid'], 'familymonitor-y291ga', '9.0.35.00_202111291330')
        if not upgrade_bytes:
            print(f'Upgrade for {device["name"]} not needed')
            return

        with open(f'{device['uid']}_upgrade.bin', 'wb') as f:
            f.write(upgrade_bytes)

        print(f'Upgrade for {device["name"]} downloaded')


if __name__ == '__main__':
    main()
