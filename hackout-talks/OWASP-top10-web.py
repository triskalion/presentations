from flask import Flask, request, render_template, render_template_string, send_from_directory, abort, jsonify
import os


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

##Template injection

# Vulnerable route where user input is directly injected into the template
@app.route('/welcome')
def welcome():
    user_controlled_injection_point = request.args.get('user_input')
    template = "<p>Welcome, " + user_controlled_injection_point + "!</p>"
    return render_template_string(template)



####################################
####################################
##API Top Ten##
#################################### 
####################################

####################################
##API3:2023 - Broken Object Property Level Authorization##
#################################### 

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
        'isAdmin': request.form.get('isAdmin', 'false')  # Mass assignment allows this to be set by user input
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

if __name__ == '__main__':
    app.run(debug=True)


# Example usage: start the Flask app
if __name__ == '__main__':
    app.run(debug=True)
