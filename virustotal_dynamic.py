import json, time
from typing import Dict, Any
from vt import Client, APIError

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name):
        title = f'{av_name} identified the file as {virus_name}'
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
        )
        super(AvHitSection, self).__init__(
            title_text=title,
            classification=Classification.UNRESTRICTED,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
        )


class VirusTotalDynamic(ServiceBase):
    def __init__(self, config=None):
        super(VirusTotalDynamic, self).__init__(config)
        self.client = None

    def start(self):
        self.log.debug("VirusTotalDynamic service started")

    def execute(self, request: ServiceRequest):
        try:
            self.client = Client(apikey=self.config.get("api_key", request.get_param("api_key")))
        except Exception as e:
            self.log.error("No API key found for VirusTotal")
            raise e

        response = self.scan_file(request)
        result = self.parse_results(response)
        request.result = result

    # noinspection PyUnusedLocal
    def scan_file(self, request: ServiceRequest):
        filename = request.file_path
        json_response = None
        with open(filename, "rb") as file_obj:
            try:
                json_response = self.client.scan_file(file=file_obj, wait_for_completion=True).to_dict()
            except APIError as e:
                if "NotFoundError" in e.code:
                    self.log.warning("VirusTotal has nothing on this file.")
                elif "QuotaExceededError" in e.code:
                    self.log.warning("Quota Exceeded. Trying again in 60s")
                    time.sleep(60)
                    return self.scan_file(request)
                else:
                    self.log.error(e)
            return json_response

    @staticmethod
    def parse_results(response: Dict[str, Any]):
        res = Result()
        url_section = ResultSection('VirusTotal Analysis',
                                    body_format=BODY_FORMAT.URL,
                                    body=json.dumps({"url": f"https://www.virustotal.com/api/v3/analyses/{response['id']}"}))
        res.add_section(url_section)
        response = response['attributes']
        scans = response['results']
        av_hits = ResultSection('Anti-Virus Detections')
        av_hits.add_line(f'Found {response["stats"]["malicious"]} AV hit(s) from '
                         f'{len(response["results"].keys())}')
        for majorkey, subdict in sorted(scans.items()):
            if subdict['category'] == "malicious":
                virus_name = subdict['result']
                av_hit_section = AvHitSection(majorkey, virus_name)
                av_hit_section.set_heuristic(1, signature=f'{majorkey}.{virus_name}')
                av_hit_section.add_tag('av.virus_name', virus_name)
                av_hits.add_subsection(av_hit_section)

        res.add_section(av_hits)

        return res
