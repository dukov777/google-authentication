# https://pbaumgarten.com/python/flask-google-auth.md

from flask import Flask, redirect, url_for, render_template, session, request
from google.oauth2.credentials import Credentials
import google.auth.transport.requests
import google.oauth2.id_token
import google_auth_oauthlib
import os
from googleapiclient.discovery import build     ## Used by Google OAuth

# Replace these with the path to your client secrets file and the desired scopes.
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", 
"https://www.googleapis.com/auth/userinfo.email", 
"openid"]

app = Flask("Google Login App")  #naming our application
app.secret_key = "GeekyHuman.com"  #it is necessary to set a password when dealing with OAuth 2.0
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #this is to set our environment to https because OAuth 2.0 only supports https environments

# client_secrets_file = "client_secrets.json"

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE, 
    scopes=SCOPES,
    redirect_uri="http://127.0.0.1:5000/oauth2callback"  #and the redirect URI is the point where the user will end up after the authorization
)

@app.route("/")
def index():
    # Check if the user is logged in.
    if "user" not in session:
        return render_template("login.html")
    # If the user is logged in, redirect to the home page.
    return render_template("login.html", user=session['user'])

@app.route("/login")
def login():
    # Generate the authorization URL.
    authorization_url, state = flow.authorization_url(
        authorization_base_url="https://accounts.google.com/o/oauth2/auth",
        access_type="offline",
        prompt="consent",
    )
    # Save the state in the session so we can verify the response.
    session["state"] = state
    # Redirect the user to the authorization URL.
    return redirect(authorization_url)

@app.route("/logout")  #the logout page and function
def logout():
    session.clear()
    return redirect("/")

## Used by Google OAuth
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}

@app.route("/oauth2callback")
def oauth2callback():
    # Verify the state parameter.
    state = session["state"]
    if request.args.get("state") != state:
        raise Exception("Invalid state parameter")
    # # Create the OAuth flow object.
    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    #     CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    # )
    # Exchange the authorization code for a credentials object.
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    # Save the credentials in the session.
    session["credentials"] = credentials_to_dict(credentials)
    
    oauth2_client = build('oauth2','v2',credentials=credentials)
    user_info= oauth2_client.userinfo().get().execute()
    session['user'] = user_info
    print(session)
    # Redirect the user to the home page.
    return redirect("/")

if __name__ == '__main__':
    app.run()


# def login_is_required(function):  #a function to check if the user is authorized or not
#     def wrapper(*args, **kwargs):
#         if "google_id" not in session:  #authorization required
#             return abort(401)
#         else:
#             return function()

#     return wrapper


# @app.route("/login")  #the page where the user can login
# def login():
#     authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
#     session["state"] = state
#     return redirect(authorization_url)




# @app.route("/logout")  #the logout page and function
# def logout():
#     session.clear()
#     return redirect("/")


# @app.route("/")  #the home page where the login button will be located
# def index():
#     return "Hello World <a href='/login'><button>Login</button></a>"


# @app.route("/protected_area")  #the page where only the authorized users can go to
# @login_is_required
# def protected_area():
#     return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"  #the logout button 


# if __name__ == "__main__":  #and the final closing function
#     app.run(debug=True)