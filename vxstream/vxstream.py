from os import path, remove
from time import sleep
from shutil import copyfileobj
from requests.auth import HTTPBasicAuth

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, \
    ModuleExecutionError

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class VxStream(ProcessingModule):
    name = "vxstream"
    description = "VxStream Sandbox features in-depth static and dynamic " \
                  "analysis techniques within sanboxed environments and is a " \
                  "malware repository created by Payload Security."
    acts_on = ["apk", "chm", "eml", "excel", "executable", "hta", "html",
               "jar", "javascript", "lnk", "msg", "pdf", "pl", "powerpoint",
               "ps1", "psd1", "psm1", "rtf", "svg", "swf", "vbe", "vbs",
               "word", "wsf", "zip"]
    generates = ["memory_dump", "pcap"]

    config = [
        {
            "name": "url",
            "type": "str",
            "default": "https://demo11.vxstream-sandbox.com/",
            "description": "Base URL of the online service."
        },
        {
            "name": "api",
            "type": "str",
            "default": "https://demo11.vxstream-sandbox.com/api/",
            "description": "URL of the API endpoint."
        },
        {
            "name": "apikey",
            "type": "str",
            "default": "3f7zqrvwpow0w8s8kc8gssow",
            "description": "API key of the service account."
        },
        {
            "name": "secret",
            "type": "str",
            "default": "1b7b64431ec654ed4db81985909e0290309d3108b07bb400",
            "description": "API key secret of the service account."
        },
        {
            "name": "environmentId",
            "type": "integer",
            "default": 100,
            "description": "Environment setting where analyzes are run."
        },
        {
            "name": "html",
            "type": "bool",
            "default": True,
            "description": "Downloads a HTML page of an analysis upon "
                           "retrieval of the report.",
            "option": True
        },
        {
            "name": "hybridanalysis",
            "type": "bool",
            "default": True,
            "description": "Enables memory dump and its automated analysis for "
                           "file submissions.",
            "option": True
        },
        {
            "name": "interval",
            "type": "integer",
            "default": 30,
            "description": "Interval in seconds of the heartbeat check for an "
                           "analysis report."
        },
        {
            "name": "memory",
            "type": "bool",
            "default": False,
            "description": "Downloads a memory dump of an analysis upon "
                           "retrieval of the report.",
            "option": True
        },
        {
            "name": "nosharevt",
            "type": "bool",
            "default": False,
            "description": "Disallow third-party downloads of the sample "
                           "submitted for analysis."
        },
        {
            "name": "pcap",
            "type": "bool",
            "default": False,
            "description": "Downloads a network traffic capture of an analysis "
                           "upon retrieval of the report.",
            "option": True
        },
        {
            "name": "timeout",
            "type": "integer",
            "default": 240,
            "description": "Timeout value in seconds of the wait time for the "
                           "end of an analysis."
        },
        {
            "name": "torenabledanalysis",
            "type": "bool",
            "default": False,
            "description": "Network traffic generated during analysis is routed "
                           "through The Onion Router (TOR) network for file "
                           "submissions.",
            "option": True
        }
    ]

    permissions = {
        "vxstream_access": "For users that have access to the VxStream Sandbox "
                           "instance. It displays a URL to the analysis on "
                           "VxStream Sandbox."
    }

    def initialize(self):
        # check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self,
                                            "Missing dependency: requests")
        # init
        self.headers = {
            "User-agent": "FAME (https://github.com/certsocietegenerale/fame) "
                          "VxStream Module"
        }

    def each_with_type(self, target, type):
        self.results = {}

        self.html = True
        self.memory = True
        self.pcap = True

        self.sha256 = "2cb713746d11f1f0cd9022aee69e3c1a47fc0a747d05131b4273b51f76a405f7"

        # submit file or url for analysis
        # self.submit(target, type)
        # wait for the analysis to be over
        # self.heartbeat()
        # retrieve the report and populate results
        self.report()

        return True

    def submit(self, target, type):
        url = self.api + "submit"
        param = {
            "auth": HTTPBasicAuth(self.apikey, self.secret),
            "data": {
                "environmentId": self.environmentId,
                "hybridanalysis": ("false", "true")[self.hybridanalysis],
                "nosharevt": ("false", "true")[self.nosharevt],
                "torenabledanalysis": ("false", "true")[self.torenabledanalysis]
            },
            "headers": self.headers,
            "verify": False
        }

        if type == "url":
            url += "url"
            param["data"]["analyzeurl"] = target
        else:
            param["files"] = {"file": open(target, 'rb')}

        res = requests.post(url, **param)

        if res.status_code != 200:
            if res.status_code == 400:
                raise ModuleExecutionError("file upload failed or an unknown "
                                           "submission error took place")
            elif res.status_code == 429:
                raise ModuleExecutionError("API key quota has been reached")
            else:
                raise ModuleExecutionError("an unspecified error took place")
        else:
            data = res.json()
            if data["response_code"] == -1:
                raise ModuleExecutionError("unsuccessful submission: " +
                                           data["response"])
            else:  # success
                self.sha256 = data["response"]["sha256"]

    def heartbeat(self):
        url = self.api + "state/" + self.sha256
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentId
            },
            "headers": self.headers
        }

        stopwatch = 0
        while stopwatch < self.timeout:
            res = requests.get(url, **param)

            if res.status_code == 200:
                data = res.json()
                if data["response_code"] == 0:
                    data = data["response"]
                    if data["state"] == "SUCCESS":
                        break

            sleep(self.interval)
            stopwatch += self.interval

        if stopwatch >= self.timeout:
            raise ModuleExecutionError("report retrieval timed out")

    def report(self):
        url = self.api + "scan/" + self.sha256
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentId,
                "type": "json"
            },
            "headers": self.headers
        }

        res = requests.get(url, **param)

        if res.status_code != 200:
            raise ModuleExecutionError("an unspecified error took place")
        else:
            data = res.json()
            if data["response_code"] == 0:
                data = data["response"][0]

                # signature
                self.add_probable_name(data["vxfamily"])
                self.results["signatures"] = data["vxfamily"]
                # tags
                for t in data["classification_tags"]:
                    self.add_tag(t)
                # iocs
                ioc = set(data["compromised_hosts"] +
                          data["domains"] + data["hosts"])
                for i in ioc:
                    self.add_ioc(i)
                # html
                if self.html:
                    param["params"]["type"] = "html"
                    msg = "unable to download the HTML page for sample"
                    self.downl(param, ".html", msg, "Report",
                               gzip=True)
                # memory
                if self.memory:
                    param["params"]["type"] = "memory"
                    msg = "unable to download the memory dump for sample"
                    self.downl(param, ".raw", msg, "memory", "memory_dump",
                               zip=True)
                # pcap
                if self.pcap:
                    param["params"]["type"] = "pcap"
                    msg = "unable to download the network traffic capture " \
                          "for sample"
                    self.downl(param, ".pcap", msg, "PCAP", "pcap",
                               gzip=True)
                # results
                self.results["analysis_start_time"] = data["analysis_start_time"]
                self.results["avdetect"] = data["avdetect"]
                self.results["environmentDescription"] = data["environmentDescription"]
                self.results["environmentId"] = data["environmentId"]
                self.results["isinteresting"] = data["isinteresting"]
                self.results["size"] = data["size"]
                self.results["submitname"] = data["submitname"]
                self.results["threatlevel"] = data["threatlevel"]
                self.results["threatscore"] = data["threatscore"]
                self.results["total_network_connections"] = data["total_network_connections"]
                self.results["total_processes"] = data["total_processes"]
                self.results["total_signatures"] = data["total_signatures"]
                self.results["type"] = data["type"]
                self.results["URL"] = self.url + "sample/" + self.sha256 + \
                                      "?environmentId=" + str(self.environmentId)
                self.results["verdict"] = data["verdict"]

    def downl(self, param, ext, msg, name,
              register=None, zip=False, gzip=False):
        url = self.api + "result/" + self.sha256
        res = requests.get(url, **param)

        if res.status_code != 200:
            self.log("error", msg + " " + self.sha256 + ": " + res.reason)
        else:
            try:
                data = res.json()
                if data["response_code"] == -1:
                    self.log("error", msg + " " + self.sha256 + ": " +
                             data["response"]["error"])
            except ValueError:
                # tmpdir = tempdir()
                # filepath = path.join(tmpdir, self.sha256 + ".pcap.gz")
                filepath = self.sha256 + ext
                if zip:
                    filepath += ".zip"
                elif gzip:
                    filepath += ".gz"

                with open(filepath, 'wb') as fd:
                    fd.write(res.content)

                if zip:
                    import zipfile
                    zip = zipfile.ZipFile(filepath, 'r')
                    zip.extractall(".")
                    zip.close()
                    # remove(filepath)
                    filepath = filepath[:-4]
                elif gzip:
                    import gzip
                    with gzip.open(filepath, 'rb') as gz:
                        with open(self.sha256 + ext, 'wb') as fd:
                            fd.write(gz.read())
                    # remove(filepath)
                    filepath = filepath[:-3]

                    # import StringIO
                    # gz = StringIO.StringIO()
                    # gz.write(res.content)
                    # gz.seek(0)
                    # fd.write(gzip.GzipFile(fileobj=gz, mode='rb').read())

                self.add_support_file(name, filepath)
                if register:
                    self.register_files(register, filepath)
                # if extract:
                #     self.add_extracted_file(filepath)

    def out(self, msg):
        from datetime import datetime
        time = datetime.utcnow().strftime("%a %d %b %Y %H:%M:%S.%f +0000 UTC")
        print "%s: %s" % (time, msg)

    def debugreq(self):
        import logging
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1

        # You must initialize logging, otherwise you'll not see debug output.
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        # self.out(res.headers)
        # self.out(str(res.status_code) + " " + res.reason)
        # self.out(res.text)
        # self.out(res.json()["response_code"])
