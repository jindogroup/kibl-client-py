# internal modules
from urllib import request, response

# external modules
from abc import ABC, abstractmethod
from base64 import b64encode
from requests.exceptions import HTTPError
import os
import requests
import json
import logging

LOGGER = logging.getLogger(__name__)


# use this form to compose the request to invoke the Kibl APIs
class KiblRequestForm():
    CONST_GET_PARSER_INFO = "reference/feed-sources"
    CONST_GET_MAPPING_SPORTS = "mapping/sports"
    CONST_GET_MAPPING_LEAGUES = "mapping/leagues"
    CONST_GET_MAPPING_FIXTURES = "mapping/fixtures"
    CONST_GET_MAPPING_SIDES = "mapping/sides"
    CONST_GET_MAPPING_SEGMENTS = "mapping/segments"
    CONST_GET_MAPPING_MARKET_TYPES = "mapping/market-types"
    CONST_GET_MAPPING_PARTICIPANTS = "mapping/participants"
    CONST_GET_REF_SPORTRS = "reference/sports"
    CONST_GET_REF_LEAGUES = "reference/leagues"
    CONST_GET_REF_SIDES = "reference/sides"
    CONST_GET_REF_SEGMENTS = "reference/segments"
    CONST_GET_INFO_FIXTURE_BY_ROTATION = "info/fixtures-by-rotations"
    CONST_GET_INFO_FIXTURES = "info/fixtures"
    CONST_UPDATE_MAPPING_FIXTURES = "mapping/fixtures"

    api_url = ''
    api_feed_id = None
    api_username = None
    api_password = None
    api_token = None
    api_info = None
    api_parameters = None
    api_bypass_cache = None


class KiblRequest(ABC):
    def __init__(self):
        pass


    def fetch(self, request_form: KiblRequestForm):
        use_cognito = False
        cognito_access_token = None

        if not os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN") is None and len(str(os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN"))) > 0:
            use_cognito = True
            cognito_access_token = str(os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN"))

        try:
            ticket = request_form.api_parameters

            # Kibl uses caching for more static conents. we can bypass it if needed
            if not request_form.api_bypass_cache is None and request_form.api_bypass_cache == True:
                ticket['from_cache'] = False

            if not ticket is None:
                try:
                    if use_cognito and not cognito_access_token is None:
                        header = {'Content-Type':'application/json', 'Authorization': cognito_access_token}
                        response = requests.post(request_form.api_url + request_form.api_info, json.dumps(ticket), headers=header)
                    else:
                        response = requests.post(request_form.api_url + request_form.api_info, json.dumps(ticket))
                except HTTPError as http_err:
                    print(http_err)
                    LOGGER.error("{} error when querying : {} : {}".format(request_form.api_info, request_form.api_url + request_form.api_info, http_err))
                    return response.status_code, None
                else:
                    LOGGER.info("{} success when querying : {}".format(request_form.api_info, request_form.api_url + request_form.api_info))
                    return response.status_code, json.loads(response.text)['result']
        except Exception as e:
            print(e)
            LOGGER.error("general error when querying : {} : {}".format(request_form.api_url + request_form.api_info, e))
            return -1, None


    def update(self, request_form: KiblRequestForm):
        use_cognito = False
        cognito_access_token = None

        if not os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN") is None and len(str(os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN"))) > 0:
            use_cognito = True
            cognito_access_token = str(os.getenv("KIBL_API_SPORTS_ACCESS_TOKEN"))

        try:
            ticket = request_form.api_parameters

            # Kibl uses caching for more static conents. we can bypass it if needed
            if not request_form.api_bypass_cache is None and request_form.api_bypass_cache == True:
                ticket['from_cache'] = request_form.api_bypass_cache   

            if not ticket is None:
                try:
                    if use_cognito and not cognito_access_token is None:
                        header = {'Content-Type':'application/json', 'Authorization': cognito_access_token}
                        response = requests.post(request_form.api_url + request_form.api_info, json.dumps(ticket), headers=header)
                    else:
                        response = requests.post(request_form.api_url + request_form.api_info, json.dumps(ticket))
                except HTTPError as http_err:
                    print(http_err)
                    LOGGER.error("{} error when querying : {} : {}".format(request_form.api_info, request_form.api_url + request_form.api_info, http_err))
                    return response.status_code, None
                else:
                    LOGGER.info("{} success when querying : {}".format(request_form.api_info, request_form.api_url + request_form.api_info))
                    return response.status_code, json.loads(response.text)['result']
        except Exception as e:
            print(e)
            LOGGER.error("general error when querying : {} : {}".format(request_form.api_url + request_form.api_info, e))
            return -1, None