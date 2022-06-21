# CAPEv2 service

This repository is an Assemblyline service that submits a file to a CAPEv2 deployment, waits for the submission to
complete, and then parses the report returned.

This repository contains mostly code adapted from the
[Assemblyline Cuckoo service](https://github.com/CybercentreCanada/assemblyline-service-cuckoo), and
was inspired by the [project](https://github.com/NVISOsecurity/assemblyline-service-cape)
created by [x1mus](https://github.com/x1mus) with support from [Sorakurai](https://github.com/Sorakurai),
[jvanwilder](https://github.com/jvanwilder), and [RenaudFrere](https://github.com/RenaudFrere) at
[NVISOsecurity](https://github.com/NVISOsecurity).

Since the REST APIv2 is the only API version that is [supported](https://capev2.readthedocs.io/en/latest/usage/api.html), we will also only be supporting this version.

It should be noted that this service grabs the `lite` format of the report bundle. So be sure you have `litereport` enabled in your `reporting.conf` file on your CAPE instance.

#### Execute multiple DLL exports
`dll.py`

This is located at `analyzer/windows/modules/packages`. It's a slightly modified
version of the upstream `dll.py` package that is able to launch multiple DLL
exports in a single run by passing the export names to execute using the
function option, separated by the comma character. ie. `function=export1,export2`.

See PR: https://github.com/kevoreilly/CAPEv2/pull/939
