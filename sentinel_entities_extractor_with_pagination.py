# This Python script extracts entities from Microsoft Sentinel incidents while supporting pagination.
# It overcomes the default limit of 50 incidents by iterating through all available incidents using the @odata.nextLink pagination feature.
# The script is currently designed to extract hostnames (endpoints) from the incidents, but it can easily be easily modified to extract other entity types such as IP addresses, accounts, URLs, etc.
# The time range for incident retrieval can be adjusted as needed.
# Useful for large environments where incidents exceed the default page size and comprehensive entity extraction is required.
# Ensure valid Azure authentication is in place before running the script.

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

# Endpoints
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://management.azure.com/.default"]
SENTINEL_INCIDENTS_API = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-09-01"

# Authenticate using MSAL
def get_access_token():
    app = msal.ConfidentialClientApplication(CLIENT_ID, CLIENT_SECRET, AUTHORITY)
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Failed to obtain token: {result}")

# Fetch endpoint (hostname) from incident entities
def get_endpoint_from_incident(incident_id, token):
    entity_url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents/{incident_id}/entities?api-version=2024-09-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(entity_url, headers=headers)
    
    if response.status_code == 200:
        entities = response.json().get("entities", [])
        for entity in entities:
            if entity.get("kind") == "Host":
                hostname = entity.get("properties", {}).get("hostName")
                return hostname
    return "No endpoint found"

# Get all incidents, handling pagination
def get_all_incidents(token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = SENTINEL_INCIDENTS_API
    all_incidents = []

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            all_incidents.extend(data.get("value", []))
            url = data.get("nextLink")  # Get next page if available
        else:
            raise Exception(f"Error fetching incidents: {response.status_code}, {response.text}")

    return all_incidents

# Filter incidents within the desired time range
def get_new_incidents(time_window_seconds):
    token = get_access_token()
    incidents = get_all_incidents(token)
    recent_incidents = []
    now = datetime.datetime.now(datetime.UTC)

    for incident in incidents:
        created_time = incident.get("properties", {}).get("createdTimeUtc", "")

        if created_time:
            created_time = created_time[:26] + "Z"
            created_time = created_time.rstrip("Z")
            time_format = "%Y-%m-%dT%H:%M:%S.%f" if "." in created_time else "%Y-%m-%dT%H:%M:%S"
            created_dt = datetime.datetime.strptime(created_time, time_format).replace(tzinfo=datetime.UTC)
            if (now - created_dt).total_seconds() <= time_window_seconds:
                incident_id = incident["name"]
                endpoint = get_endpoint_from_incident(incident_id, token)
                recent_incidents.append({"Incident ID": incident_id, "Endpoint": endpoint})

    return recent_incidents

# Main execution
if __name__ == "__main__":
    # Example for 7 days = 604800 seconds, 14 days = 1209600 seconds
    time_window_seconds = 86400  # 24 hours
    new_incidents = get_new_incidents(time_window_seconds)
    if new_incidents:
        print(f"Found {len(new_incidents)} new incidents in the last {time_window_seconds // 86400} days:")
        for incident in new_incidents:
            print(f"- Incident ID: {incident['Incident ID']}, Endpoint: {incident['Endpoint']}")
    else:
        print("No new incidents found.")
