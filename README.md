# Garena Account Checker

A Python-based tool for checking the validity and status of Garena accounts.

## Features

- Bulk account checking capability
- Colorized console output for better readability
- Progress bar for bulk operations
- Detailed error reporting
- Session management with automatic retry
- Saves results to output file
- Handles captcha detection

## Prerequisites

- Python 3.x
- pip (Python package installer)

## Installation

1. Clone this repository or download the files:
```bash
git clone https://github.com/yourusername/Acc-Checker-main.git
cd Acc-Checker-main
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Create an input file (e.g., `accounts.txt`) with accounts in the following format:
```
username1:password1
username2:password2
username3:password3
```

2. Run the script:
```bash
python account_checker.py
```

3. When prompted:
   - Enter the name of your input file containing the accounts
   - Enter the name for the output file where results will be saved

4. The script will process each account and display results in real-time with color coding:
   - 🟢 Green: Successful login and account verification
   - 🔴 Red: Failed login attempts or errors
   - 🟡 Yellow: Retry attempts

## Output Format

The results will be saved in your specified output file with the following format:
```
[SUCCESS] Account: username:password, User Info: {account_details}
[FAILED] Account: username:password, Status: {error_message}
```

## Features in Detail

- **Session Management**: Automatically handles session expiration and retries
- **Error Handling**: Comprehensive error catching and reporting
- **Rate Limiting**: Built-in delays to prevent IP blocking
- **Progress Tracking**: Visual progress bar for bulk operations
- **Captcha Detection**: Alerts when captcha verification is required

## Dependencies

- requests: For making HTTP requests
- tqdm: For progress bar visualization
- colorama: For colored console output

## Important Notes

- This tool is for educational purposes only
- Ensure you have permission to check the accounts
- Be aware of Garena's terms of service and usage policies
- Use reasonable delays between checks to avoid IP blocks

## Disclaimer

This tool is provided for educational purposes only. Users are responsible for ensuring they have the right to check any accounts and must comply with Garena's terms of service and applicable laws.

## Author

@Shin

## License

This project is for educational purposes only. Use at your own risk.
