# VxFame
*VxFame* is the name given to the project that integrates [FAME](https://github.com/certsocietegenerale/fame), an open-source malware analysis framework, with the Application Programming Interface (API) of VxStream Sandbox, an online sandbox for malware analysis. The FAME module that integrates with the API of VxStream Sandbox is called `vxstream`. The structure of the module is as follows:
* `vxstream/__init__.py`: required in order to identify `vxstream` as a package that is recognized by FAME;
* `vxstream/details.html`: Jinja2 code for displaying results;
* `vxstream/requirements.txt`: a list of Python dependencies;
* `vxstream/vxstream.py`: the entry point of the module that integrates with the API of VxStream.

(...)

The `vxstream.py` and `details.html` files are described in detailed in the next two sections, respectively. The last section overviews the usage of the module.

# `vxstream.py`


A FAME `ProcessingModule` subclass named `VxStream` (...)

The functions of the module can be described as follows:
* `initialize`:
* `each_with_type`:
* `submit`:
* `heartbeat`:
* `report`:
* `downl`:

(...)


# `details.html`

Jinja2 code

(...)

# Usage

(...)

for offline testing
* `./utils/run.sh utils/single_module.py -t vxstream <sample>`


for interface testing
copy the module to `fame/modules/community/processing/vxstream`
* `./utils/run.sh webserver.py`
* `./utils/run.sh worker.py`

http://127.0.0.1:4200/
