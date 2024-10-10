from napalm import get_network_driver

def main():
    driver = get_network_driver('hios')
    device = driver(
        hostname='82.141.17.146',
        username='user',
        password='public'
    )

    try:
        device.open()
        print("Connected to the device")

        interfaces = device.get_interfaces()
        print("Device interfaces:")
        print(interfaces)

    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        device.close()
        print("Connection closed")

if __name__ == '__main__':
    main()
