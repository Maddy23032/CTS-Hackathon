Here's the markdown content for running your project:

```markdown
# Project Setup and Execution Guide

## Prerequisites

- Python 3.x installed on your system
- Git installed for repository cloning
- Internet connection for cloning the repository and testing

## Installation and Setup

### 1. Clone the Repository

```
git clone https://github.com/Maddy23032/CTS-Hackathon.git
```

### 2. Navigate to Project Directory

```
cd <project-directory-name>
```


### 3. Install Dependencies (if applicable)

```
pip install -r requirements.txt
```

## Running the Application

### Basic Command Structure

```
python main.py <target-url> --oast --verbose
```

### Parameters

- `<target-url>`: The URL of the vulnerable website you want to scan
- `--oast`: Enable Out-of-Band Application Security Testing
- `--verbose`: Enable verbose output for detailed logging

### Example Usage

```
python main.py http://zero.webappsecurity.com/ --oast --verbose
```

### Multiple Target Testing

To test multiple vulnerable sites, run the command separately for each target:

```
python main.py http://testaspnet.vulnweb.com/ --oast --verbose
python main.py http://testhtml5.vulnweb.com/ --oast --verbose
python main.py http://testphp.vulnweb.com/ --oast --verbose
```

## Output

The scanner will provide detailed output due to the `--verbose` flag, showing:
- Scan progress
- Detected vulnerabilities
- OAST callback information
- Detailed results and recommendations

## Notes

- Ensure you have permission to test the target websites
- Use only on authorized targets or dedicated vulnerable testing applications
- The `--oast` flag enables advanced out-of-band testing techniques
- Verbose mode provides comprehensive logging for analysis and debugging

## Troubleshooting

If you encounter any issues:
1. Verify Python is installed and accessible via command line
2. Check that all dependencies are properly installed
3. Ensure the target URL is accessible and properly formatted
4. Verify you have necessary permissions to scan the target
```

This markdown file provides a complete guide for setting up and running your vulnerability scanner project with the specified command structure and parameters.
