import requests
import json
from .dataclasses import DnsMessage


class UmbrellaApi:
    """
    Class is used for making API calls to a Cisco Umbrella instance.
    """

    def __init__(self, umbrella_api, logger):
        """Constructor for UmbrellaApi.

        Args:
            umbrella_api (str): Url for API endpoint
        """
        self.api = umbrella_api
        self.token = None
        self.logger = logger
        retry_strategy = requests.packages.urllib3.util.retry.Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get_umbrella_token(self, key, secret):
        """Function to authenticate the user and retrieve the auth token

        Args:
            key (str): Key
            secret (str): Secret

        Raises:
            requests.RequestException: Auth url couldn't be requested
        """
        header = {'Content-Type': 'application/json'}
        data = {"grant_type": "client_credentials"}
        auth = (key, secret)
        try:
            response = self.session.post(f"{self.api}/auth/v2/token", data=data, headers=header, auth=auth, timeout=5)
        except Exception as e:
            self.logger.critical(f"Couldn't request {self.api}/auth/v2/token. Aborting!")
            exit(0)
        else:
            json_response = json.loads(response.text)
            self.token = json_response["access_token"]
        
    def get_dns_frames(self, timeframe):
        """Function retrieves the dns frames from umbrella API

        Args:
            timeframe (int): Timeframe to look in

        Returns:
            List[DnsMessage]: List of DnsMessage objects
        """
        header = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }
        data = {
            "from": f"-{timeframe}minutes",
            "to": "now",
            "limit": "5000",
            "categories": "65,67,68",
            "verdict": "blocked"
        }
        try:
            response = self.session.get(f"{self.api}/reports/v2/activity/dns", data=data, headers=header, timeout=5)
        except Exception as e:
            self.logger.critical(f"Couldn't request {self.api}/reports/v2/activity. Aborting!")
            exit(0)
        else:
            return DnsMessage.from_json_list(json.loads(response.text))
