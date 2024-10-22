import csv
import json
import copy
from datetime import datetime
from dataclasses import dataclass, field


@dataclass(init=True, repr=True)
class DnsMessage:
    """Dataclass to hold information about the found DNS Requests.
    """

    external_ip: str
    umbrella_timestamp: str
    dns_question_name: str
    dns_question_type: str
    origin: str = None
    command_and_control: int = None
    malware: int = None
    phishing: int = None
    newly_seen: int = None
    potentially_harmfull: int = None
    graylog_searched_until: str = None
    source_ip: str = None
    # TODO: If client domain in Umbrella take data from umbrella
    source_domain: str = None
    dns_question_class: str = None
    source: str = None
    graylog_timestamp: str = None
    graylog_message: str = None

    @classmethod
    def from_json(cls, json_object):
        """Creates a DnsMessage object from a json object.

        Args:
            json_object (json): Json-Object

        Returns:
            DnsMessage: Created DnsMessage Object
        """
        umbrella_timestamp = f"{json_object['date']}T{json_object['time']}.000Z"
        umbrella = cls(json_object['externalip'], umbrella_timestamp,
                       json_object['domain'], json_object['querytype'])
        umbrella.set_categories(json_object['categories'])
        umbrella.source_domain = json_object['identities'][0]['label']
        umbrella.source_ip= json_object['internalip']
        return umbrella

    @classmethod
    def from_json_list(cls, json_list):
        """Creates a list of DnsMessage objects from a json list.

        Args:
            json_list (json): Json-List

        Returns:
            List[DnsMessage]: List of DnsMessage objects
        """
        return [cls.from_json(message) for message in json_list['data']]

    @classmethod
    def from_cache(cls, json_dict):
        return {domain: cls(**entry) for domain, entry in json_dict.items()}
    
    def set_categories(self, categories):
        """Sets the categories of the instances

        Args:
            categories (json): Json with categories
        """
        for category in categories:
            if category['id'] == 65:
                self.command_and_control = 1
            if category['id'] == 67:
                self.malware = 1
            if category['id'] == 68:
                self.phishing = 1
            if category['id'] == 108:
                self.newly_seen = 1
            if category['id'] == 109:
                self.potentially_harmfull = 1

    def set_graylog_data_from_json_list(self, json_list):
        """Function sets graylog data from a json list.
        If the list contains multiple objects the original DnsMessage object is deepcopied for every object in the list.

        Args:
            json_list (json): Json list

        Returns:
            List[DnsMessage]: List of DnsMessage objects
        """
        dns_messages = []
        for index, message in enumerate(json_list):
            if index == 0:
                if "source_ip" in message['message']:
                    self._set_graylog_data(message)
                    dns_messages.append(self)
            else:
                if "source_ip" in message['message']:
                    dns_message = copy.deepcopy(self)
                    dns_message._set_graylog_data(message)
                    dns_messages.append(dns_message)
        return dns_messages

    def _set_graylog_data(self, json):
        """Internal function to set the graylog data of the object

        Args:
            json (json): Json object with data
        """
        self.source_ip = json['message']['source_ip']
        if "source_domain" in json['message']:
            self.source_domain = json['message']['source_domain']
        else:
            self.source_domain = None
        self.dns_question_class = json['message']['network_dns_question_class']
        self.source = json['message']['source']
        self.graylog_timestamp = json['message']['timestamp']
        self.graylog_message = json['message']['message']

    def to_graylog(self):
        return {
            "source_ip": self.source_ip,
            "source_domain": self.source_domain,
            "network_dns_resolved_ip": self.external_ip,
            "network_dns_question_name": self.dns_question_name,
            "network_dns_question_type": self.dns_question_type,
            "network_dns_question_class": self.dns_question_class,
            "graylog_searched_until": self.graylog_searched_until,
            "umbrella_timestamp": self.umbrella_timestamp,
            "origin": self.origin,
            "command_and_control": self.command_and_control,
            "malware": self.malware,
            "phishing": self.phishing,
            "newly_seen": self.newly_seen,
            "potentially_harmfull": self.potentially_harmfull
        }

    def to_cache(self):
        return {
            self.dns_question_name: {
                "umbrella_timestamp": self.umbrella_timestamp,
                "graylog_searched_until": self.graylog_searched_until,
                "external_ip": self.external_ip,
                "dns_question_name": self.dns_question_name,
                "dns_question_type": self.dns_question_type,
                "command_and_control": self.command_and_control,
                "malware": self.malware,
                "phishing": self.phishing,
                "newly_seen": self.newly_seen,
                "potentially_harmfull": self.potentially_harmfull
            }
        }
