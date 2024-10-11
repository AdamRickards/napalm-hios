#!/usr/bin/env python3
from napalm.base.exceptions import ConnectionException
from napalm_hios.hios import HIOSDriver
import datetime
import json
from pathlib import Path
import sys
import time

class LiveDeviceTest:
    def __init__(self, hostname, username, password, timeout=60, ping_destination='8.8.8.8', ping_count=5):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ping_destination = ping_destination
        self.ping_count = ping_count
        self.results = {
            'test_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'hostname': hostname,
                'username': username,
                'ping_destination': ping_destination,
                'ping_count': ping_count
            },
            'protocol_tests': {}
        }

        self.test_methods = [
            'get_facts',
            'get_interfaces',
            'get_snmp_information',
            'get_environment',
            'get_arp_table',
            'get_config',
            'get_interfaces_counters',
            'get_interfaces_ip',
            'get_lldp_neighbors',
            'get_lldp_neighbors_detail',
            'get_mac_address_table',
            'get_ntp_servers',
            'get_ntp_stats',
            'get_optics',
            'get_users',
            'get_vlans',
            'ping',
            'get_lldp_neighbors_detail_extended'
        ]

        # Define CLI commands here
        self.cli_commands = ['show vlan brief', 'show telnet']  # Editable list of commands to execute

    def test_protocol(self, protocol):
        """Run all tests using a specific protocol."""
        protocol_results = {
            'connection': False,
            'methods': {},
            'start_time': datetime.datetime.now().isoformat()
        }
        
        driver = None
        try:
            # Initialize driver with specific protocol
            driver = HIOSDriver(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                optional_args={'protocol_preference': [protocol]}
            )
            
            # Test connection
            print(f"\nTesting {protocol.upper()} connection...")
            driver.open()
            protocol_results['connection'] = True
            print(f"✓ Connection successful")
            
            # Test each method
            for method_name in self.test_methods:
                try:
                    method = getattr(driver, method_name)
                    start_time = time.time()
                    if method_name == 'ping':
                        result = method(destination=self.ping_destination, count=self.ping_count)
                        protocol_results['methods'][method_name] = {}
                        self.analyze_ping_result(result, protocol_results['methods'][method_name])
                    else:
                        result = method()
                    end_time = time.time()
                    
                    protocol_results['methods'][method_name] = {
                        'success': True,
                        'result': result,
                        'duration': round(end_time - start_time, 2)
                    }
                    print(f"✓ {method_name} completed in {protocol_results['methods'][method_name]['duration']}s")
                except Exception as e:
                    protocol_results['methods'][method_name] = {
                        'success': False,
                        'error': str(e),
                        'duration': round(time.time() - start_time, 2)
                    }
                    print(f"✗ {method_name} failed after {protocol_results['methods'][method_name]['duration']}s")
                    print(f"  Error: {str(e)}")

            # Test CLI commands
            for command in self.cli_commands:
                print(f"Testing CLI command: {command}...")
                try:
                    start_time = time.time()
                    result = driver.cli([command])  # Call the cli method with the list of commands
                    end_time = time.time()
                    print(f"✓ {command} completed in {round(end_time - start_time, 2)}s")
                    protocol_results['methods'][command] = {
                        'success': True,
                        'result': result,
                        'duration': round(end_time - start_time, 2)
                    }
                except Exception as e:
                    print(f"✗ {command} failed after {round(time.time() - start_time, 2)}s")
                    print(f"  Error: {str(e)}")
                    protocol_results['methods'][command] = {
                        'success': False,
                        'error': str(e),
                        'duration': round(time.time() - start_time, 2)
                    }
                    
        except ConnectionException as e:
            protocol_results['connection_error'] = str(e)
            print(f"✗ Connection failed: {str(e)}")
        except Exception as e:
            protocol_results['error'] = str(e)
            print(f"✗ Unexpected error: {str(e)}")
        finally:
            if driver:
                try:
                    driver.close()
                except:
                    pass
            protocol_results['end_time'] = datetime.datetime.now().isoformat()
                
        self.results['protocol_tests'][protocol] = protocol_results
        # Save results after each protocol test in case of failures
        self.save_results()
        return protocol_results

    def analyze_ping_result(self, result, ping_results):
        """Analyze and add detailed information about ping results."""
        # Check if the result indicates an error
        if 'error' in result:
            ping_results['success'] = False
            ping_results['error'] = result['error']
            return  # Early exit if there's an error

        # If there are no errors, analyze the successful ping results
        ping_results['success'] = True
        
        # Set details under a separate key
        ping_results['details'] = {
            'probes_sent': result['success'].get('probes_sent', 0),
            'packet_loss': result['success'].get('packet_loss', 100),
            'rtt_min': result['success'].get('rtt_min', 0),
            'rtt_avg': result['success'].get('rtt_avg', 0),
            'rtt_max': result['success'].get('rtt_max', 0),
            'rtt_stddev': result['success'].get('rtt_stddev', 0),
            'results': result['success'].get('results', [])  # Include the results of the individual pings
        }

    def run_all_tests(self):
        """Run tests for all protocols."""
        self.test_protocol('ssh')

    def generate_markdown(self):
        """Generate markdown report from test results."""
        timestamp = datetime.datetime.fromisoformat(self.results['test_info']['timestamp'])
        
        md_content = [
            "# HIOS Driver Live Device Test Results\n",
            f"Test run on: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n",
            f"Device: {self.results['test_info']['hostname']}\n",
            f"Ping Destination: {self.results['test_info']['ping_destination']}\n",
            f"Ping Count: {self.results['test_info']['ping_count']}\n",
            "## Protocol Test Results\n"
        ]
        
        for protocol, results in self.results['protocol_tests'].items():
            md_content.append(f"### {protocol.upper()}\n")
            
            # Connection status
            connection_status = "✓ Connected" if results['connection'] else "✗ Connection Failed"
            md_content.append(f"Connection Status: {connection_status}\n")
            
            if 'connection_error' in results:
                md_content.append(f"Connection Error: {results['connection_error']}\n")
            
            if results['connection'] and 'methods' in results:
                md_content.append("\nMethod Results:\n")
                for method, data in results['methods'].items():
                    status = "✓" if data['success'] else "✗"
                    duration = data.get('duration', 'N/A')
                    md_content.append(f"\n#### {status} {method} (Duration: {duration}s)\n")
                    
                    if data['success']:
                            md_content.append("```json\n")
                            md_content.append(json.dumps(data['result'], indent=2))
                            md_content.append("\n```\n")
                    else:
                        md_content.append(f"Error: {data['error']}\n")
            
            start_time = datetime.datetime.fromisoformat(results['start_time'])
            end_time = datetime.datetime.fromisoformat(results['end_time'])
            duration = (end_time - start_time).total_seconds()
            md_content.append(f"\nTotal duration: {round(duration, 2)}s\n")
            md_content.append("\n---\n")
        
        return "".join(md_content)

    def save_results(self, filename="test_live_device.md"):
        """Save test results to markdown file."""
        markdown = self.generate_markdown()
        output_path = Path(filename)
        output_path.write_text(markdown)
        print(f"\nTest results saved to {output_path.absolute()}")

def main():
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        print("Usage: test_live_device.py <hostname> <username> <password> [ping_destination] [ping_count]")
        sys.exit(1)
        
    hostname, username, password = sys.argv[1:4]
    ping_destination = sys.argv[4] if len(sys.argv) > 4 else '8.8.8.8'
    ping_count = int(sys.argv[5]) if len(sys.argv) > 5 else 5
    
    tester = LiveDeviceTest(hostname, username, password, ping_destination=ping_destination, ping_count=ping_count)
    tester.run_all_tests()

if __name__ == "__main__":
    main()