import json
import requests


class GraylogApi:
    """
    Class is used for making API calls to a graylog server.
    """

    def __init__(self, url, token, logger):
        """Constructor for class GraylogApi.

        Args:
            url (str): URL pointing to Graylog API endpoint
            token (str): Access-Token for authentification against the API
            logger: Logger object
        """
        self.url = url
        self.token = (token, "token")
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

    def get_messages(self, dns_message, start_datetime, end_datetime, stream, limit=None):
        """API call to get all messages from a specific dns request.

        Args:
            dns_message (DnsMessage): DnsMessage instance
            limit (int, optional): Limits for messages to fetch. Defaults to None.

        Returns:
            List[DnsMessage]: List of DnsMessage
        """
        header = {'Accept': 'application/json'}
        if limit:
            uri = f"{self.url}/search/universal/absolute?query=network_dns_question_name:{dns_message.dns_question_name}%20AND%20_exists_:source_ip&from={start_datetime}&to={end_datetime}&decorate=true&filter=streams:{stream}&limit={limit}"
        else:
            uri = f"{self.url}/search/universal/absolute?query=network_dns_question_name:{dns_message.dns_question_name}%20AND%20_exists_:source_ip&from={start_datetime}&to={end_datetime}&decorate=true&filter=streams:{stream}"
        try:
            request = self.session.get(uri, headers=header,
                                auth=self.token, verify=False, timeout=5)
        except Exception as e:
            self.logger.critical(f"Couldn't request {uri}. Aborting!")
            exit(0)
        else:        
            json_response = json.loads(request.text)
            if 'messages' in json_response:
                if len(json_response['messages']) > 0:
                    messages = dns_message.set_graylog_data_from_json_list(json_response['messages'])
                    return messages
                else:
                    return [dns_message]
            else:
                return [dns_message]
