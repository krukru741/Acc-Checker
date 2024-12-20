Account Checker
account_checker.py is a Python script designed to automate the process of checking user account statuses on the Garena platform. It performs the following key functions:
Hashing: Generates MD5 hashes for passwords and encodes them using SHA-256.
Captcha Handling: Fetches and saves captcha images.
Login Management: Attempts to log in with provided credentials and retrieves session cookies.
User Info Retrieval: Fetches user information using session cookies.
Bulk Account Checking: Reads account credentials from a file, checks each account, and logs results to an output file.
Progress Display: Utilizes tqdm for a visual progress bar during bulk checks.
Usage
Run the script, provide an input file with username:password pairs, and specify an output file for results.
