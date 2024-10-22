from configparser import ConfigParser
from pathlib import Path

class Config:
    """
    Class holds all config information needed for the programming
    """

    def __init__(self, config_file):
        """Constructor for class Config

        Args:
            config_file (Path): Path object for config file.
        """
        config = ConfigParser()
        with open(config_file) as f:
            config.read_file(f)
        self.umbrella_key = config['umbrella']['key']
        self.umbrella_secret = config['umbrella']['secret']
        self.umbrella_api = "https://api.umbrella.com"
        self.timeframe_minutes = config['umbrella']['timeframe_minutes']
        self.defined_networks_file = Path(config['umbrella']['defined_networks_file'])

        self.graylog_token = config['graylog']['token']
        self.graylog_api = config['graylog']['api']
        self.graylog_dns_log_stream = config['graylog']['dns_log_stream']

        self.cache_file = Path(config['caching']['cache_file'])
        self.cache_ttl_hours = int(config['caching']['cache_ttl_hours'])
        if not self.cache_file.exists() or not self.cache_file.is_file():
            print(f"Can't find file {self.cache_file}. Creating it.")
            self.cache_file.touch()
        self.log_file = Path(config['caching']['log_file'])
        if not self.log_file.exists() or not self.log_file.is_file():
            self.log_file.touch()

        self.logging_host = config['logging']['host']
        self.logging_port = int(config['logging']['port'])
        if int(config['logging']['tls']):
            self.logging_tls = True
            if 'ca_certs' not in config['logging']:
                print("ca_certs needs to be set for TLS.\nAborting!")
                exit(0)
            if 'certfile' not in config['logging']:
                print("certfile needs to be set for TLS.\nAborting!")
                exit(0)
            if 'keyfile' not in config['logging']:
                print("keyfile needs to be set for TLS.\nAborting!")
                exit(0)
            self.logging_ca_certs = Path(config['logging']['ca_certs'])
            self.logging_certfile = Path(config['logging']['certfile'])
            self.logging_keyfile = Path(config['logging']['keyfile'])
            if not self.logging_ca_certs.exists() or not self.logging_ca_certs.is_file():
                print(f"Can't open file {self.logging_ca_certs}. Either it doesn't exist or isn't a file.\nAborting!")
                exit(0)
            if not self.logging_certfile.exists() or not self.logging_certfile.is_file():
                print(f"Can't open file {self.logging_certfile}. Either it doesn't exist or isn't a file.\nAborting!")
                exit(0)
            if not self.logging_keyfile.exists() or not self.logging_keyfile.is_file():
                print(f"Can't open file {self.logging_keyfile}. Either it doesn't exist or isn't a file.\nAborting!")
                exit(0)
        else:
            self.logging_tls = False
            self.logging_ca_certs = None
            self.logging_certfile = None
            self.logging_keyfile = None

