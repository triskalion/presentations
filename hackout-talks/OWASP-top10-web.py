from flask import Flask, request, render_template, render_template_string, send_from_directory, abort, jsonify, redirect
import os, requests, sqlite3
from urllib.parse import urlparse


app = Flask(__name__)

####################################
##A01:2021 – Broken Access Control##
#################################### 

##IDOR-horizontal

from flask import Flask, request

app = Flask(__name__)

# Simulated user database
users_data = {
    1: {"name": "Alice", "role": "user", "data": "Alice's sensitive data"},
    2: {"name": "Bob", "role": "user", "data": "Bob's sensitive data"}
}

# Simulated logged-in user (Alice)
logged_in_user_id = 1  # Assume Alice is logged in

# Insecure function to get user data from an HTTP request
@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    # Get the requested_user_id from the query parameters (e.g., /get_user_data?user_id=2)
    requested_user_id = int(request.args.get('user_id'))
    
    # No proper access control to check if the logged-in user is requesting their own data
    if requested_user_id in users_data:
        user_info = users_data[requested_user_id]["data"]
        return render_template('result.html', user_info=user_info)
    else:
        return render_template('result.html', user_info="User not found")


##IDOR-horizontal-FIXED


# Simulated user database
users_data = {
    1: {"name": "Alice", "role": "user", "data": "Alice's sensitive data"},
    2: {"name": "Bob", "role": "user", "data": "Bob's sensitive data"}
}

# Simulated logged-in user (Alice)
logged_in_user_id = 1  # Assume Alice is logged in

# Secure function to get user data from an HTTP request
@app.route('/get_user_data_secure', methods=['GET'])
def get_user_data_secure():
    # Get the requested_user_id from the query parameters (e.g., /get_user_data_secure?user_id=2)
    requested_user_id = int(request.args.get('user_id'))
    
    # Ensure the logged-in user can only access their own data
    if logged_in_user_id == requested_user_id:
        return jsonify(users_data[requested_user_id])
    else:
        return "Access Denied", 403


####################################
##A03:2021 – Injection##
#################################### 

##XSS injection

# Sign-up page
@app.route('/signupxss', methods=['GET', 'POST'])
def signupxss():
    users.clear()
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Store the user (without sanitizing the name, making it vulnerable to XSS)
        users.append({'name': name, 'email': email, 'password': password})
        return redirect('/admin')
    
    return render_template('signup.html')

# Admin page where the XSS vulnerability will manifest
@app.route('/admin')
def admin():
    # Display the list of users (without escaping their names)
    return render_template('admin.html', users=users)

##Template injection

# Vulnerable route where user input is directly injected into the template
@app.route('/welcome')
def welcome():
    user_controlled_injection_point = request.args.get('user_input')
    template = "<p>Welcome, " + user_controlled_injection_point + "!</p>"
    return render_template_string(template)



#########################################################
#########################################################
##API Top Ten##
#########################################################
#########################################################

##########################################################
##API3:2023 - Broken Object Property Level Authorization##
##########################################################

##Mass Assignment
# In-memory storage to simulate user data
users = []

@app.route('/signup', methods=['GET'])
def show_signup():
    # Render the signup.html page when the user visits /signup.html
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    # Manually assign only allowed fields (no isAdmin field exposed)
    user = {
        'username': request.form.get('username'),
        'email': request.form.get('email'),
        'password': request.form.get('password'),
        'isAdmin': request.form.get('isAdmin', 'false')
    }

    #user['isAdmin'] = False
    users.append(user)  # Add the user to the list (simulated storage)

    response_data = {
        "message": "User created successfully!",
        "users": users
    }

    # If isAdmin is set to true, include a secret message in the response
    if user['isAdmin'].lower() == 'true':  # Check if the user set isAdmin to 'true'
        response_data["secret"] = "You have access to the admin secrets!"
    

    response =  response = jsonify(response_data), 201
    users.clear()
    return response


###########################################
##API7:2023 - Server Side Request Forgery##
###########################################

@app.route('/fetch-url', methods=['GET'])
def fetch_url():
    # Get the 'url' parameter from the query string
    target_url = request.args.get('url')
    
    # If no URL is provided, return an error message
    if not target_url:
        return jsonify({"error": "Please provide a URL using the 'url' parameter."}), 400
    
    try:
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            return jsonify({"error": "Invalid URL format."}), 400
         
        # Remove scheme and prepare the host header (e.g., www.example.com)
        host_header = parsed_url.netloc
        
        # Make a GET request to the URL with the custom Host header
        headers = {
            'Host': host_header,# Set Host header to the netloc (host without the scheme)
            'Secret': 'HackoutTalks#3'
        }
        # Fetch the content of the URL
        response = requests.get(target_url, headers=headers)
        
        return response.text
        # If the request was successful, return the content
        #if response.status_code == 200:
        #    return response.text
        #else:
        #    return jsonify({"error": f"Failed to fetch the URL. Status code: {response.status_code}"}), 400
    except Exception as e:
        # Handle exceptions (e.g., invalid URLs or network errors)
        return jsonify({"error": str(e)}), 500


@app.route('/secrets', methods=['GET'])
def secrets():
    # Check if the 'Secret' header is present and its value is 'HackoutTalks#3'
    secret_header = request.headers.get('Secret')
    
    if secret_header == 'HackoutTalks#3':
        # Return a secret message if the header is correct
        return jsonify({"secret": "You have accessed the secret area!"})
    else:
        # Return 403 Forbidden if the header is missing or incorrect
        return jsonify({"error": "Forbidden: Public access is denied!"}), 403


###########################################
##API8:2023 - Security Misconfiguration####
###########################################
# Sensitive information
SECRET_API_KEY = "API_KEY_1234567890"
DATABASE_PASSWORD = "super_secret_password"

def fake_http_call():
    # Fake HTTP call using the actual API key
    response = requests.get(f"https://fakeapi.com/data?apikey={SECRET_API_KEY}")
    return response

def fake_db_connection():
    # Fake DB connection using the actual password
    conn = sqlite3.connect(f"file:fake_db?password={DATABASE_PASSWORD}", uri=True)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fake_table")
    result = cursor.fetchall()
    return result

@app.route('/error')
def trigger_error():
    try:
        # Call to a fake HTTP request (more lines of code shown in stack trace)
        response = fake_http_call()
        
        # Call to a fake database connection (more lines of code shown in stack trace)
        result = fake_db_connection()

        # Adding some additional code before the error
        temp_var = "Some temporary value"
        another_var = "Another temporary value"
        
        # Intentionally cause an error
        result = 1 / 0  # This will raise ZeroDivisionError
    except Exception as e:
        # Trigger an error to show more lines of the stack trace
        raise ZeroDivisionError("This is an intentional error after using API key and DB password") 
# Example usage: start the Flask app
if __name__ == '__main__':
    app.run(debug=True)
