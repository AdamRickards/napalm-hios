# Network Optics Data Collection Tool

This Python script collects and analyzes optical information from network devices using the NAPALM-HIOS driver. It processes the collected data and generates an Excel report with power measurements and quality metrics.

## System Requirements

- Python 3.7 or higher (enforced by runtime check)
- Network connectivity to target devices
- Write permissions in the script directory

## Features

- Collects optical data from multiple network devices simultaneously
- Validates IPv4 addresses automatically
- Automatic retry mechanism for failed connections
- Comprehensive logging system with console output
- Generates detailed Excel reports with:
  - Input/Output power measurements
  - Distance-based quality calculations
  - Automatic problem detection
  - Conditional formatting for problematic values
- Secure credential management through configuration file
- Error handling and recovery mechanisms
- Progress tracking and execution timing
- Configurable through command-line arguments
- Resource path handling for both development and compiled executable environments
- Windows executable available in /windows/get_optics.exe for easy deployment

## Installation

1. Ensure Python 3.7 or higher is installed
2. Install required packages:
```bash
pip install -r requirements.txt
```

## Configuration

Create a `script.cfg` file with the following format:
```
username your_username
password your_password
192.168.1.1
192.168.1.2
# Add more IP addresses as needed
```

Configuration Rules:
- Lines starting with '#' are treated as comments
- Username and password must be specified at the beginning
- Each subsequent line should contain a single valid IPv4 address
- Empty lines are ignored
- Invalid entries will be logged and skipped

## Usage

### Basic Usage
```bash
python get_optics.py
```

### Command Line Arguments
```bash
python get_optics.py [-h] [-c CONFIG] [-o OUTPUT] [-r RETRIES] [-d DELAY] [-t TIMEOUT] [-v]
```

Arguments:
- `-h, --help`: Show help message and exit
- `-c, --config CONFIG`: Path to configuration file (default: script.cfg)
- `-o, --output OUTPUT`: Path to output Excel file (default: network_data.xlsx)
- `-r, --retries RETRIES`: Number of connection retries (default: 3)
- `-d, --delay DELAY`: Delay between retries in seconds (default: 5)
- `-t, --timeout TIMEOUT`: Connection timeout in seconds (default: 30)
- `-v, --verbose`: Enable verbose logging

Examples:
```bash
# Use custom configuration file
python get_optics.py -c my_config.cfg

# Change output file location
python get_optics.py -o /path/to/output.xlsx

# Adjust retry settings
python get_optics.py -r 5 -d 10

# Enable verbose logging
python get_optics.py -v
```

## Output Files

### Excel Report (network_data.xlsx)
- Automatically created in the script directory
- If the default filename is locked, creates a timestamped alternative
- Contains sheets with:
  - Host information
  - Interface details
  - Input/Output power measurements
  - Configurable distance field
  - Automated quality calculations
  - Problem detection highlighting

### Log File (optics_collection_YYYYMMDD_HHMMSS.log)
- Created for each script run
- Contains detailed operation logs
- Includes:
  - Connection attempts
  - Data collection status
  - Error messages
  - Execution timing

## Excel Report Details

### Columns:
- Host: Device IP address
- Interface: Network interface identifier
- Input Power: Measured input power
- Output Power: Measured output power
- Distance: User-input field (meters)
- Quality: Calculated based on input power and distance
- Problem: Automatic detection of potential issues

### Quality Metrics
- Quality is calculated as Input Power / Distance
- Problems are flagged when quality deviates >50% from average
- Problematic rows are highlighted in red
- Data validation ensures positive distance values

## Error Handling

The script includes comprehensive error handling for:
- Invalid configuration files
- Network connectivity issues
- Device authentication failures
- Data collection errors
- File access issues
- Malformed data

All errors are:
- Logged to the session log file
- Displayed in the console
- Included in the Excel report where applicable
- Handled with automatic retry mechanisms where appropriate

## Windows Executable

A pre-compiled Windows executable is available in the `/windows/get_optics.exe` directory. This executable:
- Requires no Python installation
- Maintains all features of the Python script
- Automatically handles resource paths
- Creates logs directory in the executable's location
- Uses the same configuration file format
- Can be run directly by double-clicking or from command line

## Notes

- The script requires valid network device credentials
- Devices must be accessible on the network
- The NAPALM-HIOS driver must be compatible with your network devices
- Excel report generation requires write permissions in the script directory
- Default connection timeout is 30 seconds per device
- Failed connections will be retried up to 3 times with 5-second delays by default
- All settings can be adjusted via command line arguments
