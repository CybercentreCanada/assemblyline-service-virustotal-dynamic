import json
import time

import requests

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT


class VTException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name):
        title = '%s identified the file as %s' % (av_name, virus_name)
        super(AvHitSection, self).__init__(
            title_text=title,
            classification=Classification.UNRESTRICTED)


class VirusTotalDynamic(ServiceBase):
    def __init__(self, config=None):
        super(VirusTotalDynamic, self).__init__(config)
        self.api_key = self.config.get("api_key")
        self.private_api = self.config.get("private_api")

    def start(self):
        self.log.debug("VirusTotal service started")

    def execute(self, request):
        filename = request.file_path
        response = self.scan_file(request, filename)
        result = self.parse_results(response)
        if self.private_api:
            # Call some private API functions
            pass

        request.result = result

    # noinspection PyUnusedLocal
    def scan_file(self, request, filename):

        # Let's scan the file
        url = self.config.get('BASE_URL') + "file/scan"
        try:
            f = open(filename, "rb")
        except:
            print("Could not open file")
            return {}

        files = {"file": f}
        values = {"apikey": self.api_key}
        r = requests.post(url, values, files=files)
        try:
            json_response = r.json()
        except ValueError:
            if r.status_code == 204:
                message = "You exceeded the public API request rate limit (4 requests of any nature per minute)"
                raise VTException(message)
            raise

        # File has been scanned, if response is successful, let's get the response

        if json_response is not None and json_response.get('response_code') <= 0:
            return json_response

        sha256 = json_response.get('sha256', 0)
        if not sha256:
            return json_response

        # Have to wait for the file scan to be available -- might take a few minutes...
        while True:
            url = self.config.get("base_url") + "file/report"
            params = {'apikey': self.api_key, 'resource': sha256}
            r = requests.post(url, params)
            try:
                json_response = r.json()
            except Exception:
                if r.status_code == 204:
                    message = "You exceeded the public API request rate limit (4 requests of any nature per minute)"
                    raise VTException(message)
                raise

            if 'scans' in json_response:
                break
            # Limit is 4 public API calls per minute, make sure we don't exceed quota
            # time.sleep(20)
            time.sleep(20)

        return json_response

    def parse_results(self, response):
        res = Result()
        response = response.get('results', response)

        if response is not None and response.get('response_code') == 204:
            message = "You exceeded the public API request rate limit (4 requests of any nature per minute)"
            raise VTException(message)
        elif response is not None and response.get('response_code') == 203:
            message = "You tried to perform calls to functions for which you require a Private API key."
            raise VTException(message)
        elif response is not None and response.get('response_code') == 1:
            url_section = ResultSection(
                'Virus total report permalink',
                body_format=BODY_FORMAT.URL,
                body=json.dumps({"url": response.get('permalink')}))
            res.add_section(url_section)

            av_hits = ResultSection('Anti-Virus Detections')
            scans = response.get('scans', response)
            av_hits.add_line(f'Found {response.get("positives")} AV hit(s) from {response.get("total")} scans.')
            for majorkey, subdict in sorted(scans.items()):
                if subdict['detected']:
                    virus_name = subdict['result']
                    av_hit_section = AvHitSection(majorkey, virus_name)
                    av_hit_section.set_heuristic(1, signature=f'{majorkey}.{virus_name}')
                    av_hit_section.add_tag('av.virus_name', virus_name)
                    av_hits.add_subsection(av_hit_section)

            res.add_section(av_hits)

        return res
