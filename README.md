# Garena Account Checker

A Python-based tool for checking the validity and status of Garena accounts.

> ⚠️ **IMPORTANT: EDUCATIONAL PURPOSES ONLY**
> 
> This project is created solely for educational purposes to demonstrate:
> - Python programming concepts
> - API interaction
> - Logging implementation
> - Error handling
> - Session management
> 
> Users are responsible for ensuring they have the right to check any accounts and must comply with Garena's terms of service and applicable laws.

## Features

- ✅ Bulk account checking from a text file
- ✅ Detailed account information display
- ✅ Session key retrieval
- ✅ Account status verification
- ✅ Clean and readable output format
- ✅ Progress bar for bulk operations
- ✅ Comprehensive error handling
- ✅ Detailed logging system

## Requirements

- Python 3.7 or higher
- Required Python packages:
  - requests
  - tqdm
  - colorama
  - pycryptodome

## Installation

1. Clone the repository:
```bash
git clone https://github.com/krukru741/Acc-Checker.git
cd Acc-Checker
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Prepare your accounts file (e.g., `accounts.txt`) with accounts in the format:
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
   - Enter the path to your accounts file
   - Enter the path where you want to save the results

## Output Format

### Successful Check
```
✅ Account Check Success
    Login: username:password
    UID: 12345678
    Username: username
    Session: session_key
    Country: PH
    Email: exa****@gmail.com
    Mobile: Not Set
    Facebook: Not Connected
    Nickname: Not Set
    Shell: 0
    Signature: signature

--------------------------------------------------------------------------------
```

### Failed Check
```
❌ Account Check Failed
    Login: username:password
    Error Details:
    Type: Authentication Error
    Message: error_msg

--------------------------------------------------------------------------------
```

## Features in Detail

- **Account Information**: Retrieves detailed account information including:
  - UID
  - Username
  - Session key
  - Country
  - Email (partially masked)
  - Mobile number (if set)
  - Facebook connection status
  - Nickname
  - Shell
  - Signature

- **Error Handling**: Comprehensive error handling for:
  - Authentication failures
  - Network issues
  - Invalid credentials
  - Session errors

- **Logging**: Detailed logging system that:
  - Creates timestamped log files
  - Records all operations
  - Helps in debugging issues

## Notes

- The tool includes a delay between checks to prevent rate limiting
- All sensitive information is partially masked in the output
- Logs are stored in the `logs` directory
- Invalid account formats are automatically skipped

## Disclaimer

This tool is for educational purposes only. Use it responsibly and in accordance with Garena's terms of service.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
