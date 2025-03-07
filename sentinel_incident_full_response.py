# This Python script retrieves the full JSON response of a specific incident from Microsoft Sentinel using its Incident ID.
# The Incident ID is a GUID string (e.g., "dd1bafef-dfa5-4067-89b9-97e3ec4e828b") and can typically be found within Sentinel logs, alerts, or API responses.
# This is useful for obtaining complete incident details for documentation, analysis, or further processing in external tools.
# To use this script, provide a valid Incident ID and ensure proper Azure authentication.
# The script outputs the full incident data in JSON format.

import requests
import json
import datetime
import msal
 
# Configuration
TENANT_ID = ""
CLIENT_ID = ""
CLIENT_SECRET = ""
SUBSCRIPTION_ID = ""
RESOURCE_GROUP = ""
WORKSPACE_NAME = ""
INCIDENT_ID = ""

# Endpoints
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://management.azure.com/.default"]
ENTITIES_URL = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents/{INCIDENT_ID}/entities?api-version=2023-02-01"

# Get access token
def get_access_token():
    app = msal.ConfidentialClientApplication(CLIENT_ID, CLIENT_SECRET, AUTHORITY)
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Failed to obtain token: {result}")

# Fetch entities of the specific incident
def get_entities():
    token = get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(ENTITIES_URL, headers=headers)

    if response.status_code == 200:
        entities = response.json()
        print(json.dumps(entities, indent=4))
    else:
        print(f"Error fetching entities: {response.status_code} - {response.text}")

# Run
if __name__ == "__main__":
    get_entities()
