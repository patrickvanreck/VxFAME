from os import path, remove
from time import sleep
from gzip import open as gzopen
from zipfile import ZipFile
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


RESPONSE_OK     = 0
RESPONSE_ERROR  = -1

GZIP    = ".gz"
ZIP     = ".zip"

class http:
    OK              = 200
    BadRequest      = 400
    TooManyRequests = 429
    json            = "application/json"
    octetstream     = "application/octet-stream"


class VxStream(ProcessingModule):
    name = "vxstream"
    description = "VxStream Sandbox features in-depth static and dynamic " \
                  "analysis techniques within sanboxed environments and is a " \
                  "malware repository created by Payload Security."
    acts_on = ["apk", "chm", "eml", "excel", "executable", "hta", "html",
               "jar", "javascript", "lnk", "msg", "pdf", "pl", "powerpoint",
               "ps1", "psd1", "psm1", "rtf", "svg", "swf", "url", "vbe", "vbs",
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
            "description": "Environment setting where analyses are run.",
            "option": True
        },
        {
            "name": "extractfiles",
            "type": "bool",
            "default": True,
            "description": "Downloads files extracted from an analysis upon "
                           "retrieval of the report.",
            "option": True
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

    def each_with_type(self, target, type):
        self.headers = {
            "User-agent": "FAME (https://github.com/certsocietegenerale/fame) "
                          "VxStream Module"
        }
        self.results = {}

        self.type = type

        # query /system/state to get environmentId
        # check for the ones for WINDOWS, ANDROID or LINUX
            # architecture field

        self.extractfiles = True
        self.html = True
        self.memory = True
        self.pcap = True
        self.sha256 = "2cb713746d11f1f0cd9022aee69e3c1a47fc0a747d05131b4273b51f76a405f7"
        # self.sha256 = "ef7ccb0f08fada65e5dca1eca10d7a76335fe2ca4769ac9f06be494c44c4cd1c"

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
        elif type == "apk":
            pass
        else:  # windows
            param["files"] = {"file": open(target, 'rb')}

        msg = "unsuccessful file submission"
        data = self.post(url, param, json=True, msg=msg)
        if data:
            self.sha256 = data["sha256"]
        else:
            raise ModuleExecutionError(msg + ", exiting")

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
        msg = "unsuccessful heartbeat check"
        while stopwatch < self.timeout:
            data = self.query(url, param, json=True, msg=msg)
            if data and data["state"] == "SUCCESS":
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

        msg = "unsuccessful report retrieval"
        data = self.query(url, param, json=True, msg=msg)
        if data:
            data = data[0]

            # signature
            self.add_probable_name(data.get("vxfamily"))
            self.results["signatures"] = data.get("vxfamily")
            # tags
            for t in data.get("classification_tags"):
                self.add_tag(t)
            # iocs
            ioc = set()
            if data.get("compromised_hosts"):
                ioc |= set(data["compromised_hosts"])
            if data.get("domains"):
                ioc |= set(data["domains"])
            if data.get("hosts"):
                ioc |= set(data["hosts"])
            for i in ioc:
                self.add_ioc(i)
            # extracted files
            if self.extractfiles:
                self.dropped(param, "dropped.zip", "Dropped Files", ZIP)
            # html
            if self.html:
                param["params"]["type"] = "html"
                self.result(param, "html", "Full Report", GZIP)
            # memory
            if self.memory:
                param["params"]["type"] = "memory"
                self.result(param, "raw", "Memory Dump", ZIP,
                            register="memory_dump")
            # pcap
            if self.pcap:
                param["params"]["type"] = "pcap"
                self.result(param, "pcap", "PCAP", GZIP,
                            register="pcap")
            # results
            self.results["analysis_start_time"] = data.get("analysis_start_time")
            self.results["avdetect"] = data.get("avdetect")
            self.results["environmentDescription"] = data.get("environmentDescription")
            self.results["environmentId"] = data.get("environmentId")
            self.results["isinteresting"] = data.get("isinteresting")
            self.results["size"] = data.get("size")
            self.results["submitname"] = data.get("submitname")
            self.results["threatlevel"] = data.get("threatlevel")
            self.results["threatscore"] = data.get("threatscore")
            self.results["total_network_connections"] = data.get("total_network_connections")
            self.results["total_processes"] = data.get("total_processes")
            self.results["total_signatures"] = data.get("total_signatures")
            self.results["type"] = data.get("type")
            self.results["URL"] = self.url + "sample/" + self.sha256 + \
                                  "?environmentId=" + str(self.environmentId)
            self.results["verdict"] = data.get("verdict")
            # screenshots
            # (...)


    def result(self, *arg, **kwarg):
        url = self.api + "result/" + self.sha256
        files = self.download(url, *arg)
        for i in files:
            self.add_support_file(arg[2], i)
        if files and kwarg.get("register"):
            self.register_files(kwarg["register"], files)

    def dropped(self, *arg):
        url = self.api + "sample-dropped-files/" + self.sha256
        files = self.download(url, *arg)
        # self.add_extraction(label, extraction)
        if files:
            for i in files:
                self.add_extracted_file(i)

    def download(self, url, param, ext, name, compression):
        files, tmp = [], []
        msg = "unsuccessful download of the " + name
        data = self.query(url, param, bin=True, msg=msg)
        if data:
            ext = "." + ext
            tmpdir = tempdir()
            file = path.join(tmpdir, self.sha256 + ext)
            decompressed = file

            if compression == GZIP:
                file += GZIP
            elif compression == ZIP:
                file += ZIP

            with open(file, 'wb') as fd:
                fd.write(data)

            if compression == GZIP:
                with gzopen(file, 'rb') as gz:
                    with open(decompressed, 'wb') as fd:
                        fd.write(gz.read())
                remove(file)
                tmp += [decompressed]
            elif compression == ZIP:
                zip = ZipFile(file, 'r')
                for i in zip.namelist():
                    tmp += [zip.extract(i, tmpdir)]
                zip.close()
                remove(file)

            files = [i for i in tmp if not i.endswith(GZIP)]
            for i in [i for i in tmp if i.endswith(GZIP)]:
                file = i[:-len(GZIP)]
                with gzopen(i, 'rb') as gz:
                    with open(file, 'wb') as fd:
                        fd.write(gz.read())
                remove(i)
                files += [file]

        return files

    def post(self, url, param, json=False, bin=False, msg=""):
        self.query(url, param, post=True, json=json, bin=bin, msg=msg)

    def query(self, url, param, post=False, json=False, bin=False, msg=""):
        if not post:
            res = requests.get(url, **param)
        else:
            res = requests.post(url, **param)

        msg = self.sha256 + ("", ": ")[bool(msg)] + msg + " - "

        if res.status_code == http.OK:
            if res.headers["Content-Type"] == http.json:
                data = res.json()
                if data["response_code"] == RESPONSE_ERROR:
                    self.log("warning", msg + data["response"]["error"])
                elif data["response_code"] == RESPONSE_OK and json:
                    return data["response"]
            elif res.headers["Content-Type"] == http.octetstream and bin:
                return res.content
            else:
                self.log("warning", msg % "unexpected response data")
        else:
            msg += "%s (HTTP" + res.status_code + " " + res.reason + ")"
            if res.status_code == http.BadRequest:
                self.log("error", msg % "file submission error")
            elif res.status_code == http.TooManyRequests:
                raise ModuleExecutionError(msg % "API key quota has been reached")
            else:
                self.log("error", msg % "unspecified error")
        return None


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

        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        # self.out(res.headers)
        # self.out(str(res.status_code) + " " + res.reason)
        # self.out(res.text)
        # self.out(res.json()["response_code"])
