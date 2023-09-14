# CAPEv2 service

This repository is an Assemblyline service that submits a file to a CAPEv2 deployment, waits for the submission to
complete, and then parses the report returned.

**NOTE**: This service **requires extensive additional installation outside of Assemblyline** before being functional. It is **not** preinstalled during a default installation.

This repository contains mostly code adapted from the
[Assemblyline Cuckoo service](https://github.com/CybercentreCanada/assemblyline-service-cuckoo), and
was inspired by the [project](https://github.com/NVISOsecurity/assemblyline-service-cape)
created by [x1mus](https://github.com/x1mus) with support from [Sorakurai](https://github.com/Sorakurai),
[jvanwilder](https://github.com/jvanwilder), and [RenaudFrere](https://github.com/RenaudFrere) at
[NVISOsecurity](https://github.com/NVISOsecurity).

## CAPE Sandbox Overview

[CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) is a fork of the open-source project [Cuckoo Sandbox](https://cuckoosandbox.org). The goal of CAPE is the addition of automated malware unpacking and config extraction. It is also the last remaining repo based on Cuckoo that is maintained and supported.

## Assemblyline's CAPE Service Overview
The CAPE service uses the CAPE REST API to send files to the CAPE nest which then hands out these tasks to a pool of victim machines (one file per victim).

**You are responsible for setting up the CAPE nest and victims**. The analysis results for the detonation of a submitted file in a victim is then retrieved,
and a summarized version of the report is displayed to the user through the Assemblyline UI. The full report is also included in the Assemblyline UI as a supplementary file for your reading pleasure.
Files that are unpacked and saved to disk are fed back into Assemblyline.

## Things to note
### Reporting
It should be noted that this service grabs the `lite` format of the report bundle. So be sure you have `litereport` enabled in your `reporting.conf` file on your CAPE instance like so:
```
[litereport]
enabled = yes
keys_to_copy = info debug signatures network curtain sysmon target
behavior_keys_to_copy = processtree processes summary
```

### REST API
There are API features that this service uses that are disabled on the public CAPE instance, therefore this service will only work with a private deployment of CAPE.

Since the REST APIv2 is the only API version that is [supported](https://capev2.readthedocs.io/en/latest/usage/api.html), we will also only be supporting this version.

Since the CAPE service will be making more than 5 requests a minute, the following `api.conf` configuration is required for the REST API on the CAPE host:
```
[api]
ratelimit = no
default_user_ratelimit = 99999999999999/s
default_subscription_ratelimit = 99999999999999/s
token_auth_enabled = yes
```

The REST API calls that are made by the CAPE service are as follows:

1. Get the status of CAPE via GET /apiv2/cuckoo/status/
2. Get the list of machines via GET /apiv2/machines/list/
3. Search for the SHA256 of a sample via GET /apiv2/tasks/search/sha256/\<sha256\>/
4. Submit a sample for file analysis via POST /apiv2/tasks/create/file/
5. Poll the task by task ID until it is completed via GET /apiv2/tasks/view/\<task-id\>/
6. Get the lite JSON report and ZIP generated via GET /apiv2/tasks/get/report/\<task-id\>/lite/zip/
7. Delete the task via GET /apiv2/tasks/delete/\<task-id\>/

By default in the `api.conf`, `[machinelist]`, `[cuckoostatus]`, and `[taskdelete]` are all disabled. You need to enable them.

In `api.conf`, it is recommended to set `token_auth_enabled = yes` and `auth_only = yes` for all REST API services.

### Recommendations for Monitoring
The CAPE service will submit a file and wait for the file to complete analysis and post-analysis processing, up until the service timeout of 800 seconds. At this point, the service will retry (2 more times) to get a result. In most cases, the only reason that the service will retry is if there is an issue with the CAPE nest. The CAPE service outputs useful error logs that you can set up Kibana alerting on for these cases when the CAPE REST API or Processor services are down or erroring. This is the recommended approach to monitor your CAPE nest.

### Service Options
#### Host Configurations
* **remote_host_details**: A list of JSON objects, where each JSON object represents a CAPE Host. Details regarding the CAPE API can be found [here](https://capev2.readthedocs.io/en/latest/usage/api.html). Each JSON object must have the following keys and values:
    * **ip** - [default: 127.0.0.1] The IP address of the machine where the CAPE API is being served
    * **port** - [default: 8000] The port where the CAPE API is being served
    * **api_key** - [default: sample_api_token] The authentication token to be passed with each API call
    * **internet_connected** - [default: false] A flag that indicates if the host has the ability to route network calls made by detonated file to the Internet

#### REST API Timeouts and Attempts
* **connection_timeout_in_seconds** - [default: 30] The timeout used to make the initial query to a host. (GET /machines/list)
* **rest_timeout_in_seconds** - [default: 120] The timeout used to make subsequent queries to a host. (GET /cuckoo/status/, POST /tasks/create/file/, GET /tasks/view/123/, GET /tasks/report/123/, DELETE /tasks/delete/123/, etc.)
* **connection_attempts** - [default: 3] The number of attempts to connect (perform a GET /machines/list/) to a host.

#### Are you using UWSGI with recycling workers?
* **uwsgi_with_recycle** * - [default: False] This configuration is to indicate if the CAPE nest's REST API that we will be interacting with is hosted by UWSGI AND UWSGI has a configuration enabled that will recycle it's workers. This is the recommended setup since using CAPE with the default cape-web.service (as of Sept 6 2022) will expose a
memory leak (https://github.com/kevoreilly/CAPEv2/issues/1112).  If you do have UWSGI enabled with recycling workers, we will see "RemoteDisconnected" and "ConnectionResetError" errors frequently, so we will silence the errors associated with them.

To install UWSGI: https://capev2.readthedocs.io/en/latest/usage/web.html?#best-practices-for-production

#### Victim configurations
* **allowed_images**: A list of strings representing the images that can be selected for detonation.
* **auto_architecture**: A JSON object consisting of the following structure:
```
    win:
        x64: []
        x86: []
    ub:
        x64: []
        x86: []
```
This is only relevant if you are using the `auto` value for the `specific_image` submission parameter.

If you have multiple images that a sample can be sent to for detonation based on type (for example Win7x64, Win10x64, Win7x86, Win10x86, WinXP, and Win7x64WithOffice), but you only want a sample to be sent to a set of those images (for example, Win7x64 and Win10x64), then you can specify those images here.

The method for interpretting this structure is that files are divided between Linux (ub) and Windows (win), as well as what processor they must be ran on (x86 or x64). If a file matches these conditions, it will be sent to all of the images specified in corresponding list. If a file does not match any of these conditions, the default list is the win + x64.

#### Analysis Configurations
* **default_analysis_timeout_in_seconds** - [default: 150] The maximum timeout for an analysis.
* **max_dll_exports_exec** - [default: 5] Limiting the amount of DLLs executed that we report about.
* **machinery_supports_memory_dumps** - [default: False] A boolean flag indicating if the CAPE machinery supports dumping memory.
* **reboot_supported** - [default: False] A boolean flag indicating if the CAPE machinery supports reboot submissions. *NB*: Reboot support is not available out of the box for CAPE.
* **extract_cape_dumps** - [default: False] CAPE extracts a lot of stuff. Some may say "TOO MUCH". Enable this setting if you want files that are uploaded to the `CAPE`, `procdump` and `macros` directories per analysis to be extracted by Assemblyline.
* **uses_https_proxy_in_sandbox** - [default: False] A boolean flag indicating if the sandbox architecture uses an HTTPS proxy to decrypt and forward traffic.

#### Reporting Configurations
* **recursion_limit** - [default: 10000] The recursion limit of the Python environment where the service is being run. This is used to traverse large JSONs generated from analysis.

#### INetSim specifications
* **random_ip_range** - [default: 192.0.2.0/24] This is the IP range that INetSim (if configured) will pick from in order to return a random IP for any DNS request that the victims make (note that this requires a patch to INetSim). This option is mainly for safelisting.
**NB** : this functionality relies on the "INetSim - Random DNS Resolution" section below.
* **inetsim_dns_servers** - [default: []] This is a list of INetSim DNS server IPs

#### API Token Configurations
* **token_key** - [default: Token] This the default keyword for the Django Rest Framework.
If you change it on the CAPE REST API, change this value to reflect that new value.

#### If the desired machine is not present in the configuration, sleep and try again?
* **retry_on_no_machine** - [default: False] If your CAPE machinery deletes machines, (AWS/Azure), there is a chance that a certain machine may not be present
for a period of time. This configuration will raise a RecoverableError in that situation, after sleeping for a certain
time period.

#### Too many monitor logs?
* **limit_monitor_apis** - [default: False] Apply a limit of 1000 to APIs that the CAPE monitor logs.

#### Should we setup the VM prior to sample execution by opening a few applications?
Note that this is only applicable to samples that would use the `doc` and `js` packages normally.
* **use_antivm_packages** - [default: False] Start some applications prior to execution.

#### You want to add your own `processtree_id` values on the fly?
* **custom_processtree_id_safelist** - [default: list()] A list of `processtree_id`s to be safelisted

### CAPE Submission Options

The options available for submissions to the CAPE service via REST API are not the clearest, but the [submission utility](https://capev2.readthedocs.io/en/latest/usage/submit.html#submission-utility) gives us a glimpse. These are the options you can select per analysis wittout having to go under the hood:

* **analysis_timeout_in_seconds** - [default: 0] Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
than this if the process being monitored exits. If the value is 0, then the analysis will default to use the value of the service parameter `default_analysis_timeout_in_seconds`.
* **specific_image** - [default: [auto, auto_all, all]] List of available images and options to send the file to (selected option is attached as tag to the task).
  * In terms of selecting a victim for detonation, this option has the third highest priority, but is the most popular with analysts.
  * This list should contain all available images, as well as the three options `auto`, `auto_all` and `all`:
    * `auto` will automatically select the image(s) that a file will be detonated on, determined by its file type. If you have a lot of images that a file can be detonated on, use the `auto_architecture` service parameter to be more specific.
    * `auto_all` will ignore the `auto_architecture` service parameter, and will send the file to all images that can detonate the file type.
    * `all` will send the file to all images in `allowed_images`.
* **dll_function** - [default: ""] Specify the DLL function to run on the DLL.
* **dump_memory** - [default: false] A boolean value indicating whether we want the memory dumped from the analysis and run volatility plugins on it. *NB*: This is very slow!
* **force_sleepskip** - [default: true] Forces a sample that attempts to sleep to wake up and skip the attempted sleep.
* **no_monitor** - [default: false] Run analysis without injecting the CAPE monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://capev2.readthedocs.io/en/latest/usage/packages.html) for more information).
* **simulate_user** - [default: true] Enables user simulation
* **reboot** - [default: false] a boolean indicating if we want an analysis to be repeated but in a simulated "rebooted" environment. *NB*: Reboot support is not available out of the box for CAPE. Also this is a development option, as users can select it without understanding what it is for and then double processing time.
* **arguments** - [default: ""] command line arguments to pass to the sample being analyzed
* **custom_options** - [default: ""] Custom options to pass to the CAPE submission.
* **clock** - [default: ""] Set virtual machine clock (format %m-%d-%Y %H:%M:%S).
* **package** - [default: ""] The name of the analysis package to run the sample with, with out-of-the-box options found [here](https://capev2.readthedocs.io/en/latest/usage/packages.html).
* **specific_machine** - [default: ""] The name of the machine that you want to run the sample on.
*NB* Used for development, when you want to send a file to a specific machine on a specific host. String format is "<host-ip>:<machine-name>" if more than one host exists. If only one host exists, then format can be either "<host-ip>:<machine-name>" or "<machine-name>".
  * This has the highest precendence for victim selection when submitting a file.
* **platform** - [default: "none"] If you don't care about the version of the operating system that you get, as long as it matches the platform, use this.
  * This has the second-highest precedence for victim selection when submitting a file.
* **routing** - [default: "none"] Specify the type of routing to be used on a per-analysis basis.
* **ignore_cape_cache** - [default: false] If there is currently a task for the same file with the exact same task options being analyzed in CAPE, this setting will ignore that task and submit a new task. Otherwise this setting will cause the service to follow the task that is currently being analyzed.
* **password** - [default: ""] The password for the password-protected file that you are submitting to CAPE.

### Deployment of CAPE Nest

See the official documentation: https://capev2.readthedocs.io/en/latest/installation/host/index.html

### Deployment of CAPE Victim

See the official documentation: https://capev2.readthedocs.io/en/latest/installation/guest/index.html

### Using Community Signatures
As per the official documentation, `cuckoo community` can be run on the nest machine in order to install signatures.

### CAPE Service Heuristics
The heuristics for the service determine the scoring of the result, and can cover a variety of behaviours. Heuristics are
raised for network calls, signature hits etc. Specifically for signature hits, we have grouped all 500+ signatures into
categories where each category is a heuristic and is representative of the signatures that fall under that category.

#### Scoring
The scores for these categories are based on the average of the signature severities (which can be found in the CAPE Community
repo on Github) for all the signatures in that category. This average was then rounded (up >= .5, down < .5) and applied to
the following range map:

> &lt;= 1: 100 (informative)
>
> &gt; 1 and &lt;= 2: 500 (suspicious)
>
> &gt; 2 and &lt;= 4: 1000 (highly suspicious)
>
> &gt; 4: 2000 (malicious)

#### ATT&CK IDs
For these categories, we have attempted to give default Mitre ATT&CK IDs to them by looking through all signatures in a category,
 and then taking the set of all ATT&CK IDs for these signatures (called `ttp` in the signature code), and if the set was a single ID
 that ID would be the default for the category. Progress is being made on finding generic IDs that can apply loosely to all signatures
 in a category when the above tactic doesn't work, such that there are defaults for all heuristics.

#### INetSim

##### Random DNS Resolution
`DNS.pm, Config.pm, inetsim_patch.conf`

These files are located at `inetsim/random_dns_patch/`. They allow an INetSim installation's DNS service to return a random IP from a given range for DNS lookups.
In order to implement this patch, replace the `DNS.pm` and `Config.pm` found wherever you're running INetSim with the files found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Then append the contents from `inetsim_patch.conf` to `/etc/inetsim/inetsim.conf`. Restart INetSim with `sudo systemctl restart inetsim.service`.

##### Geo-IP Service Patch
`HTTP.pm`

This file is located at `inetsim/geo_ip_service_patch/`. It allows an INetSim installation's HTTP service to return a fake response for a geo-IP service lookup.
In order to implement this patch, replace the `HTTP.pm` found wherever you're running INetSim with the file found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Restart INetSim with `sudo systemctl restart inetsim.service`.

### Assemblyline System Safelist
#### CAPE-specific safelisted items
The file at `al_config/system_safelist.yaml` contains suggested safelisted values that can be added to the Assemblyline system safelist
either by copy-and-pasting directly to the text editor on the page `https://<Assemblyline Instance>/admin/tag_safelist` or through the [Assemblyline Client](https://github.com/CybercentreCanada/assemblyline_client).
