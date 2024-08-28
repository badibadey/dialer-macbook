import requests
import logging
from requests.auth import HTTPBasicAuth

class AudioCodesAPI:
    def __init__(self, client_id, secret_key, bot, host="livehub.audiocodes.io"):
        self.client_id = client_id
        self.secret_key = secret_key
        self.bot = bot
        self.host = host
        self.max_retries = 3

    def start_call(self, phone_number):
        url = f"https://livehub.audiocodes.io/api/v1/actions/dialout"
        auth = HTTPBasicAuth(self.client_id, self.secret_key)
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "bot": self.bot,
            "target": f"tel:{phone_number}",
            "machineDetection": "disconnect"
        
        }
        response = requests.post(url, auth=auth, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Start call request response: {data}")
            return data['conversationId']
        else:
            logging.error(f"Failed to start call: {response.status_code} - {response.text}")
            raise Exception("Failed to start call")

    def get_bearer_token(self):
        url = f"https://{self.host}/oauth/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.secret_key
        }
        response = requests.post(url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            logging.info(f"Bearer token obtained: {token_data}")
            return token_data['access_token']
        else:
            logging.error(f"Failed to obtain bearer token: {response.status_code} - {response.text}")
            raise Exception("Failed to obtain bearer token")

    def get_call_details(self, conversationId):
        url = f"https://livehub.audiocodes.io/api/v1/Calls/?filter=(botConversationId={conversationId})"
        token = self.get_bearer_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        logging.info(f"Requesting call details for conversationId: {conversationId}")
        for attempt in range(self.max_retries):
            response = requests.get(url, headers=headers)
            logging.info(f"Get call details request response status code: {response.status_code}")
            logging.info(f"Get call details request response content: {response.content}")

            if response.status_code == 200:
                data = response.json()
                logging.info(f"Received call details: {data}")
                if not data or not data['calls']:
                    logging.error("Empty response received from API")
                    raise Exception("Empty response received from API")
                
                call_data = data['calls'][0]  # Pobieramy pierwszy element z listy 'calls'
                return {
                    'callId': call_data.get('callId'),
                    'status': 'Completed' if call_data.get('successful') else 'Failed',
                    'terminationDescription': call_data.get('terminationDescription'),
                    'setupTime': call_data.get('setupTime'),
                    'connectTime': call_data.get('connectTime'),
                    'endTime': call_data.get('endTime'),
                    'durationSeconds': call_data.get('durationSeconds'),
                    'successful': call_data.get('successful'),
                    'machineDetection': call_data.get('terminationDescription') == 'Machine Detected'
                }

            elif response.status_code == 401:
                logging.error("Authentication failed. Check your credentials.")
                raise Exception("Authentication failed")
            else:
                logging.error(f"Failed to get call details: {response.status_code} - {response.text}")

        raise Exception("Failed to get call details after max retries")
