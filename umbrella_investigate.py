# Umbrella Investigate
# Copyright (C) 2024 NetUSE AG
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import graypy
import json
import dateutil.parser
from pathlib import Path
from argparse import ArgumentParser
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from umbrella_investigate import Config, UmbrellaApi, GraylogApi, DnsMessage

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("./umbrella_investigate.conf"), help="Specify the used config file. If "
                        "none is given"
                        "./umbrella_investigate.conf"
                        "is used")
    return parser.parse_args()


if __name__ == "__main__":
    import requests
    requests.packages.urllib3.disable_warnings()


    program = "umbrella_investigate"
    args = parse_args()
    config = Config(args.config)

    logger = logging.getLogger(program)
    if config.logging_tls:
        logger.addHandler(graypy.GELFTLSHandler(host=config.logging_host, port=config.logging_port, debugging_fields=False,
                                                validate=True, ca_certs=config.logging_ca_certs,
                                                certfile=config.logging_certfile, keyfile=config.logging_keyfile))
    else:
        logger.addHandler(graypy.GELFTCPHandler(host=config.logging_host, port=config.logging_port, debugging_fields=False))


    network_logger = logging.getLogger(f"{program}.network")
    network_logger.setLevel(logging.CRITICAL)
    file_handler = logging.FileHandler(config.log_file)
    file_handler.setLevel(logging.CRITICAL)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    network_logger.addHandler(file_handler)


    # Step 1
    # Load cache and remove entries older than the TTL 
    dns_cache_data = None
    today = datetime.now(timezone.utc)
    delete_old_reports = []
    if config.cache_file.stat().st_size: 
        with open(config.cache_file, "r") as f:
            dns_cache_data = DnsMessage.from_cache(json.loads(f.read()))
        for domain, cache in dns_cache_data.items():
            cache.origin = "Cache"
            umbrella_last_reported = dateutil.parser.parse(cache.umbrella_timestamp)
            if umbrella_last_reported < today-timedelta(hours=config.cache_ttl_hours):
                delete_old_reports.append(domain)
        for domain in delete_old_reports:
            dns_cache_data.pop(domain, None)
        del delete_old_reports
    else:
        dns_cache_data = dict()

    # Step 2. Retrieve list from Umbrella 

    umbrella = UmbrellaApi(config.umbrella_api, network_logger)
    umbrella.get_umbrella_token(config.umbrella_key, config.umbrella_secret)
    umbrella_messages = umbrella.get_dns_frames(config.timeframe_minutes)

    # Step 3. Update cached data
    for message in umbrella_messages:
        if message.dns_question_name in dns_cache_data:
            dns_cache_data[message.dns_question_name].umbrella_timestamp = message.umbrella_timestamp
        else:
            dns_cache_data[message.dns_question_name] = message

    # Step 4. Correlate data from graylog searches and submit findings 
    defined_networks = []
    if config.defined_networks_file:
        with open(config.defined_networks_file, "r") as file:
            defined_networks = [line.strip() for line in file]

    graylog = GraylogApi(config.graylog_api, config.graylog_token, network_logger)
    for _, message in dns_cache_data.items():
        if message.graylog_searched_until:
            start_datetime = message.graylog_searched_until
        else:
            start_datetime = today - timedelta(hours=config.cache_ttl_hours)
            start_datetime = start_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Request came from a defined network
        # will be looked up in graylog
        if message.source_domain in defined_networks:
            dns_messages = graylog.get_messages(message, start_datetime, today.strftime('%Y-%m-%dT%H:%M:%S.%fZ'), config.graylog_dns_log_stream)
            for dns_message in dns_messages:
                dns_message.graylog_searched_until = today.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                logging_data = {
                    'program': program,
                    **dns_message.to_graylog()
                }
                logger.critical(msg=f"{program} found request to {dns_message.dns_question_name}", extra=logging_data)

        # Request was made from a computer with umbrella client
        else:
            logging_data = {
                'program': program,
                **message.to_graylog()
            }
            logger.critical(msg=f"{program} found request to {message.dns_question_name}", extra=logging_data)

        message.graylog_searched_until = today.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    with open(config.cache_file, "w") as f:
        dns_cache = {}
        for _, cache in dns_cache_data.items():
            dns_cache.update(cache.to_cache())
        f.write(json.dumps(dns_cache, indent=4))
