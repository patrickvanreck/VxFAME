# VxFame
*VxFame* is the name given to the project that integrates [FAME](https://certsocietegenerale.github.io/fame/), an open-source malware analysis framework written in Python 2.7.x, with the RESTful Application Programming Interface (API) of VxStream Sandbox, an online sandbox for malware analysis belonging to Payload Security. The FAME module that integrates with the API of VxStream Sandbox is called `vxstream`. The structure of the module is valid with the FAME development instructions and is as follows:
* `vxstream/__init__.py`: empty file that identifies `vxstream` as a valid Python package to be recognized by FAME;
* `vxstream/details.html`: HTML and Jinja2 template code for displaying results graphically in the web interface;
* `vxstream/requirements.txt`: list of Python dependencies that the module uses, depicting only [`requests`](https://github.com/requests/requests) for HTTP interaction;
* `vxstream/vxstream.py`: the Python entry point of the module that integrates with the API of VxStream Sandbox.

The `vxstream` module was developed while considering both the usefulness and completeness of its functionality with the VxStream Sandbox API in relation to the FAME framework. These considerations are realized in the module as features of analysis of malware and URLs and of retrieval of reports and data, which constitute the purpose of the module as set by FAME. FAME is licensed under GNU GPLv3 and its source code is available at its [main GitHub repository](https://github.com/certsocietegenerale/fame). Most modules developed for FAME are also licensed under GNU GPLv3 and are available at a [second GitHub repository](https://github.com/certsocietegenerale/fame_modules). FAME is documented at [Read the Docs](https://fame.readthedocs.io/en/latest/).

The `vxstream/vxstream.py` and `vxstream/details.html` files are described in detail in the next two sections, respectively. The section that follows those lists all the API resources used by the module. The next to last section overviews the usage of the module, while the very last one lists resources consulted throughout development.

# `vxstream/vxstream.py`

Most modules developed for FAME are subclasses of `ProcessingModule`, which is meant to be the base class for modules that perform some automated analysis of files or URLs. The purpose of `vxstream` fits the role of `ProcessingModule` and is therefore a subclass of it called `VxStream`.

The methods of the module can be described as follows:
* `initialize`: checks for the presence of `requests` during module initialization;
* `each_with_type`: defines the workflow of an analysis for each file or URL;
* `submit`: submits a file or URL for analysis to `/api/submit` or `/api/submiturl`, respectively;
* `heartbeat`: checks the status of an analysis on `/api/state` according to a timeout value;
* `report`: retrieves the report of an analysis from `/api/scan`, downloads additional data from `/api/result` and populates `self.results`;
* `result`: wraps `download` to target `/api/result/` and to register downloaded files;
* `dropped`: wraps `download` to target `/api/sample-dropped-files` and to mark extracted files;
* `download`: handles downloaded files according to a certain compression algorithm and marks decompressed files as support files;
* `post`: wraps `query` to change the type of HTTP request to `POST`;
* `query`: conducts HTTP `GET` (default) or `POST` requests to the VxStream Sandbox API and handles predefined response errors.

The module is developed with consistency in terms of nomenclature and purpose, particularly in variables used in different methods that have the same purpose. Some of those are described as follows:
* `data`: `dict` with parsed JSON data or `str` with binary response data from a HTTP request;
* `msg`: `str` with an error message to be logged;
* `param`: `dict` with `requests` fields for HTTP requests with `requests.get` or `requests.post`;
* `url`: `str` with the full URL of the API resource to be queried, excluding HTTP `GET` parameters.

# `vxstream/details.html`

Jinja2 code

(...)

# VxStream Sandbox API List
The `vxstream` module consumes a selected few API resources from VxStream Sandbox to achieve its integration with FAME and thereby fulfil its purpose of malware analysis and reporting. The full list and description of API resources used by `vxstream` is, without any particular order, the following:
* `/api/submit`: used to submit a file for analysis;
* `/api/submiturl`: used to submit a URL for analysis;
* `/api/state`: used to retrieve status information of an analysis;
* `/api/scan`: used to retrieve summary information of an analysis;
* `/api/result`: used to retrieve particular result data of an analysis, namely full HTML reports, memory dumps and network traffic captures;
* `/api/sample-dropped-files/`: used to download potentially malicious files dropped during an analysis;
* `/system/state`: used to determine the available analysis environments.

# Usage

(...)


copy the module to `fame/modules/community/processing/vxstream`

* for offline testing
```
./utils/run.sh utils/single_module.py -t vxstream <sample>
```


for interface testing
* `./utils/run.sh webserver.py`:
* `./utils/run.sh worker.py`: FAME workers handle task queues and make sure that module dependencies are met before actually launching modules

http://127.0.0.1:4200/

# Resources
https://certsocietegenerale.github.io/fame/<br />
https://github.com/certsocietegenerale/fame<br />
https://github.com/certsocietegenerale/fame_modules<br />
https://fame.readthedocs.io/en/latest/
