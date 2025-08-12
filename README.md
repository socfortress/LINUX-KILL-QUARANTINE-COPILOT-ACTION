## Kill-Suspicious-Process.sh

This script terminates a specified process by PID, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Kill-Suspicious-Process.sh` script attempts to kill a process by its PID, records the executable path, and outputs the result in JSON format for active response workflows.

### Script Details

#### Core Features

1. **Process Termination**: Attempts to kill the specified process by PID.
2. **Executable Path Reporting**: Reports the path of the process binary.
3. **Status Reporting**: Indicates success or failure of the termination.
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging**: Provides timestamped log messages for each action.

### How the Script Works

#### Command Line Execution
```bash
./Kill-Suspicious-Process.sh <pid>
```

#### Parameters

| Parameter | Type   | Description |
|-----------|--------|-------------|
| `<pid>`   | int    | The process ID to terminate (required) |
| `LOG`     | string | `/var/ossec/active-response/active-responses.log` (output JSON log) |

### Script Execution Flow

#### 1. Initialization Phase
- Validates the PID argument
- Logs the start of the script execution

#### 2. Kill Logic
- Attempts to kill the process with the specified PID
- Records the executable path
- Logs the result and status

#### 3. JSON Output Generation
- Formats the result into a JSON object
- Writes the JSON result to the active response log

#### 4. Completion Phase
- Logs the duration of the script execution

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Kill-Suspicious-Process.sh",
  "pid": "1234",
  "exe": "/usr/bin/malware",
  "status": "killed",
  "reason": "Process killed successfully",
  "copilot_soar": true
}
```

#### Error Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Kill-Suspicious-Process.sh",
  "pid": "1234",
  "exe": "/usr/bin/malware",
  "status": "failed",
  "reason": "Failed to kill process",
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to terminate processes
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to kill the specified process
2. **Invalid PID**: Provide a valid process ID
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging by reviewing script output

### Contributing

When modifying this script:
1. Maintain the process termination and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
