import requests
import json  # Add missing import for the json module

# Azure AD app registration details
tenant_id = 'ab24cf62-0cef-45e9-b9a2-c475226bc50a'
client_id = '3a8c9b6c-312b-4503-8c79-85bbed57db16'
client_secret = 'ur78Q~MEre3FBYd6-6thoLjuZ4fLxrQ-Ssihoaop'

# Endpoint for obtaining the access token
token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

# Headers
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

# Data (payload)
data = {
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': 'https://graph.microsoft.com/.default'
}

# Send a POST request to the endpoint
response = requests.post(token_url, headers=headers, data=data)

# Parse the JSON response
json_response = response.json()

# Extract the access token
access_token = json_response['access_token']

print(access_token)