# This Python script retrieves entities from Microsoft Sentinel incidents by making use of appropriate Sentinel API endpoints.
# A common use case is integrating with other tools, allowing the extracted entities to be passed along for further actions.
# The time frame for incident retrieval can be easily adjusted to target a specific period.
# While this script is currently configured to extract hostnames (endpoints) from incidents, it can be easily modified to retrieve other entity types such as IP addresses, accounts, and more.
# Note: This script fetches only the first 50 incidents. 
# For retrieving more than 50 incidents, please refer to the pagination-enabled script also available in this repository.

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
SENTINEL_INCIDENTS_API = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01"

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
    entity_url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents/{incident_id}/entities?api-version=2023-02-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(entity_url, headers=headers)

    hostnames = []
    if response.status_code == 200:
        entities = response.json().get("entities", [])
        for entity in entities:
            if entity.get("kind") == "Host":
                hostname = entity.get("properties", {}).get("hostName")
                if hostname:
                    hostnames.append(hostname)
    return hostnames


def get_new_incidents():
    token = get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(SENTINEL_INCIDENTS_API, headers=headers)
    if response.status_code == 200:
        incidents = response.json().get("value", [])
        recent_incidents = []
        endpoints_found = []
        now = datetime.datetime.now(datetime.UTC)

        for incident in incidents:
            created_time = incident.get("properties", {}).get("createdTimeUtc", "")

            if created_time:
                created_time = created_time[:26] + "Z"
                created_dt = datetime.datetime.strptime(created_time.rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.UTC)
                if (now - created_dt).total_seconds() <= 86400: #Last 24 hours
                    incident_id = incident["name"]
                    hostnames = get_endpoint_from_incident(incident_id, token)
                    if hostnames:
                        endpoints_found.extend(hostnames)
                        recent_incidents.append({"Incident ID": incident_id, "Endpoints": hostnames})
                    else:
                        recent_incidents.append({"Incident ID": incident_id, "Endpoints": ["No endpoint found"]})

        return recent_incidents, len(endpoints_found)
    else:
        raise Exception(f"Error fetching incidents: {response.status_code}, {response.text}")


if __name__ == "__main__":
    new_incidents, total_endpoints = get_new_incidents()
    if new_incidents:
        print(f"Found {len(new_incidents)} new incidents in the last 24 hours and {total_endpoints} endpoints:")
        for incident in new_incidents:
            endpoints_str = ", ".join(incident["Endpoints"])
            print(f"- Incident ID: {incident['Incident ID']}, Endpoints: {endpoints_str}")
    else:
        print("No new incidents found.")
