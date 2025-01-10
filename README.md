[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_cape-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-cape)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-cape)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-cape)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-cape)](./LICENSE)
# CAPE Service

This Assemblyline service submits files to a CAPEv2 deployment and parses the report returned.

## Service Details
**NOTE**: This service **requires extensive additional installation outside of Assemblyline** before being functional. It is **not** preinstalled during a default installation.

This repository contains mostly code adapted from the
[Assemblyline Cuckoo service](https://github.com/CybercentreCanada/assemblyline-service-cuckoo), and
was inspired by the [project](https://github.com/NVISOsecurity/assemblyline-service-cape)
created by [x1mus](https://github.com/x1mus) with support from [Sorakurai](https://github.com/Sorakurai),
[jvanwilder](https://github.com/jvanwilder), and [RenaudFrere](https://github.com/RenaudFrere) at
[NVISOsecurity](https://github.com/NVISOsecurity).

### CAPE Sandbox Overview

[CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) is a fork of the open-source project [Cuckoo Sandbox](https://cuckoosandbox.org). The goal of CAPE is the addition of automated malware unpacking and config extraction. It is also the last remaining repo based on Cuckoo that is maintained and supported.

### Assemblyline's CAPE Service Overview

The CAPE service uses the CAPE REST API to send files to the CAPE nest which then hands out these tasks to a pool of victim machines (one file per victim).

`You are responsible for setting up the CAPE nest and victims`. The analysis results for the detonation of a submitted file in a victim is then retrieved,
and a summarized version of the report is displayed to the user through the Assemblyline UI. The full report is also included in the Assemblyline UI as a supplementary file for your reading pleasure.
Files that are unpacked and saved to disk are fed back into Assemblyline.

### Things to note

#### Reporting

It should be noted that this service grabs the `lite` format of the report bundle. So be sure you have `litereport` enabled in your `reporting.conf` file on your CAPE instance like so:

```
[litereport]
enabled = yes
keys_to_copy = info debug signatures network curtain sysmon target
behavior_keys_to_copy = processtree processes summary
```

#### REST API

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

#### Recommendations for Monitoring

The CAPE service will submit a file and wait for the file to complete analysis and post-analysis processing, up until the service timeout of 800 seconds. At this point, the service will retry (2 more times) to get a result. In most cases, the only reason that the service will retry is if there is an issue with the CAPE nest. The CAPE service outputs useful error logs that you can set up Kibana alerting on for these cases when the CAPE REST API or Processor services are down or erroring. This is the recommended approach to monitor your CAPE nest.

#### Service Options

##### Host Configurations

- `remote_host_details`: A list of JSON objects, where each JSON object represents a CAPE Host. Details regarding the CAPE API can be found [here](https://capev2.readthedocs.io/en/latest/usage/api.html). Each JSON object must have the following keys and values:
  - `ip` - [default: 127.0.0.1] The IP address of the machine where the CAPE API is being served
  - `port` - [default: 8000] The port where the CAPE API is being served
  - `api_key` - [default: sample_api_token] The authentication token to be passed with each API call
  - `internet_connected` - [default: false] A flag that indicates if the host has the ability to route network calls made by detonated file to the Internet
  - `inetsim_connected` - [default: false] A flag that indicates if the host has the ability to route network calls made by detonated file to INetSim

##### REST API Timeouts and Attempts

- `connection_timeout_in_seconds` - [default: 30] The timeout used to make the initial query to a host. (GET /machines/list)
- `rest_timeout_in_seconds` - [default: 120] The timeout used to make subsequent queries to a host. (GET /cuckoo/status/, POST /tasks/create/file/, GET /tasks/view/123/, GET /tasks/report/123/, DELETE /tasks/delete/123/, etc.)
- `connection_attempts` - [default: 3] The number of attempts to connect (perform a GET /machines/list/) to a host.

##### Are you using UWSGI with recycling workers?

- `uwsgi_with_recycle` \* - [default: False] This configuration is to indicate if the CAPE nest's REST API that we will be interacting with is hosted by UWSGI AND UWSGI has a configuration enabled that will recycle it's workers. This is the recommended setup since using CAPE with the default cape-web.service (as of Sept 6 2022) will expose a
  memory leak (https://github.com/kevoreilly/CAPEv2/issues/1112). If you do have UWSGI enabled with recycling workers, we will see "RemoteDisconnected" and "ConnectionResetError" errors frequently, so we will silence the errors associated with them.

To install UWSGI: https://capev2.readthedocs.io/en/latest/usage/web.html?#best-practices-for-production

##### Victim configurations

- `allowed_images`: A list of strings representing the images that can be selected for detonation.
- `auto_architecture`: A JSON object consisting of the following structure:

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

##### Analysis Configurations

- `default_analysis_timeout_in_seconds` - [default: 150] The maximum timeout for an analysis.
- `max_dll_exports_exec` - [default: 5] Limiting the amount of DLLs executed that we report about.
- `machinery_supports_memory_dumps` - [default: False] A boolean flag indicating if the CAPE machinery supports dumping memory.
- `reboot_supported` - [default: False] A boolean flag indicating if the CAPE machinery supports reboot submissions. _NB_: Reboot support is not available out of the box for CAPE.
- `extract_cape_dumps` - [default: False] CAPE extracts a lot of stuff. Some may say "TOO MUCH". Enable this setting if you want files that are uploaded to the `CAPE` and `procdump` directories per analysis to be extracted by Assemblyline. Note that you still have to select "deep_scan" after this setting is enabled if you want all of the CAPE dumps, otherwise the service will be choosey about which dumps are extracted.
- `uses_https_proxy_in_sandbox` - [default: False] A boolean flag indicating if the sandbox architecture uses an HTTPS proxy to decrypt and forward traffic.
- `suspicious_accepted_languages` - [default: []] This is a list of languages in the "Accepted-Language" HTTP header that should be flagged as suspicious.

##### Reporting Configurations

- `recursion_limit` - [default: 10000] The recursion limit of the Python environment where the service is being run. This is used to traverse large JSONs generated from analysis.

##### INetSim specifications

- `random_ip_range` - [default: 192.0.2.0/24] This is the IP range that INetSim (if configured) will pick from in order to return a random IP for any DNS request that the victims make (note that this requires a patch to INetSim). This option is mainly for safelisting.
  `NB` : this functionality relies on the "INetSim - Random DNS Resolution" section below.
- `inetsim_dns_servers` - [default: []] This is a list of INetSim DNS server IPs

##### API Token Configurations

- `token_key` - [default: Token] This the default keyword for the Django Rest Framework.
  If you change it on the CAPE REST API, change this value to reflect that new value.

##### If the desired machine is not present in the configuration, sleep and try again?

- `retry_on_no_machine` - [default: False] If your CAPE machinery deletes machines, (AWS/Azure), there is a chance that a certain machine may not be present
  for a period of time. This configuration will raise a RecoverableError in that situation, after sleeping for a certain
  time period.

##### Too many monitor logs?

- `limit_monitor_apis` - [default: False] Apply a limit of 1000 to APIs that the CAPE monitor logs.

##### Should we setup the VM prior to sample execution by opening a few applications?

Note that this is only applicable to samples that would use the `doc` and `js` packages normally.

- `use_antivm_packages` - [default: False] Start some applications prior to execution.

##### You want to add your own `processtree_id` values on the fly?

- `custom_processtree_id_safelist` - [default: list()] A list of `processtree_id`s to be safelisted

##### You want to cache CAPE results every day because the CAPE system does not change that frequently?

- `update_period` - [default: 24] The period/interval (in hours) in which signatures/YARA rules/configuration extractors are updated on the CAPE nest.

#### CAPE Submission Options

The options available for submissions to the CAPE service via REST API are not the clearest, but the [submission utility](https://capev2.readthedocs.io/en/latest/usage/submit.html#submission-utility) gives us a glimpse. These are the options you can select per analysis wittout having to go under the hood:

- `analysis_timeout_in_seconds` - [default: 0] Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
  than this if the process being monitored exits. If the value is 0, then the analysis will default to use the value of the service parameter `default_analysis_timeout_in_seconds`.
- `specific_image` - [default: [auto, auto_all, all]] List of available images and options to send the file to (selected option is attached as `tag` to the CAPE task).
  - In terms of selecting a victim for detonation, this option has the third highest priority, but is the most popular with analysts.
  - This list should contain all available images, as well as the three options `auto`, `auto_all` and `all`:
    - The string representing an available image is a `tag` in machineries such as KVM, QEMU, etc., or `pool_tag` in machineries such as Azure. When declaring your machines/scale sets in your machinery configuration file in CAPE, you can include specific details about that entry in the `tags` field, such as "win10", "winxp" or "office2016". By including these items also in "specific_image" list in the Assemblyline CAPE service, you can submit files directly to these machines based on the tag.
    - `auto` will automatically select the image(s) that a file will be detonated on, determined by its file type. If you have a lot of images that a file can be detonated on, use the `auto_architecture` service parameter to be more specific.
    - `auto_all` will ignore the `auto_architecture` service parameter, and will send the file to all images that can detonate the file type.
    - `all` will send the file to all images in `allowed_images`.
- `dll_function` - [default: ""] Specify the DLL function to run on the DLL.
- `dump_memory` - [default: false] A boolean value indicating whether we want the memory dumped from the analysis and run volatility plugins on it. _NB_: This is very slow!
- `force_sleepskip` - [default: true] Forces a sample that attempts to sleep to wake up and skip the attempted sleep.
- `no_monitor` - [default: false] Run analysis without injecting the CAPE monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://capev2.readthedocs.io/en/latest/usage/packages.html) for more information).
- `simulate_user` - [default: true] Enables user simulation
- `reboot` - [default: false] a boolean indicating if we want an analysis to be repeated but in a simulated "rebooted" environment. _NB_: Reboot support is not available out of the box for CAPE. Also this is a development option, as users can select it without understanding what it is for and then double processing time.
- `arguments` - [default: ""] command line arguments to pass to the sample being analyzed
- `custom_options` - [default: ""] Custom options to pass to the CAPE submission.
- `clock` - [default: ""] Set virtual machine clock (format %m-%d-%Y %H:%M:%S).
- `package` - [default: ""] The name of the analysis package to run the sample with, with out-of-the-box options found [here](https://capev2.readthedocs.io/en/latest/usage/packages.html).
- `specific_machine` - [default: ""] The name of the machine that you want to run the sample on.
  _NB_ Used for development, when you want to send a file to a specific machine on a specific host. String format is "<host-ip>:<machine-name>" if more than one host exists. If only one host exists, then format can be either "<host-ip>:<machine-name>" or "<machine-name>".
  - This has the highest precendence for victim selection when submitting a file.
- `platform` - [default: "none"] If you don't care about the version of the operating system that you get, as long as it matches the platform, use this.
  - This has the second-highest precedence for victim selection when submitting a file.
- `routing` - [default: "none"] Specify the type of routing to be used on a per-analysis basis.
- `ignore_cape_cache` - [default: false] If there is currently a task for the same file with the exact same task options being analyzed in CAPE, this setting will ignore that task and submit a new task. Otherwise this setting will cause the service to follow the task that is currently being analyzed.
- `password` - [default: ""] The password for the password-protected file that you are submitting to CAPE.
- `monitored_and_unmonitored` - [default: false] This submission parameter will submit two tasks to CAPE, one with the monitor enabled, and another with the monitor disabled. Use wisely since it doubles the load on CAPE.

#### Deployment of CAPE Nest

See the official documentation: https://capev2.readthedocs.io/en/latest/installation/host/index.html

#### Deployment of CAPE Victim

See the official documentation: https://capev2.readthedocs.io/en/latest/installation/guest/index.html

#### Using Community Signatures

As per the official documentation, `cuckoo community` can be run on the nest machine in order to install signatures.

#### CAPE Service Heuristics

The heuristics for the service determine the scoring of the result, and can cover a variety of behaviours. Heuristics are
raised for network calls, signature hits etc. Specifically for signature hits, we have grouped all 500+ signatures into
categories where each category is a heuristic and is representative of the signatures that fall under that category.

##### Scoring

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

##### ATT&CK IDs

For these categories, we have attempted to give default Mitre ATT&CK IDs to them by looking through all signatures in a category,
and then taking the set of all ATT&CK IDs for these signatures (called `ttp` in the signature code), and if the set was a single ID
that ID would be the default for the category. Progress is being made on finding generic IDs that can apply loosely to all signatures
in a category when the above tactic doesn't work, such that there are defaults for all heuristics.

##### INetSim

###### Random DNS Resolution

`DNS.pm, Config.pm, inetsim_patch.conf`

These files are located at `inetsim/random_dns_patch/`. They allow an INetSim installation's DNS service to return a random IP from a given range for DNS lookups.
In order to implement this patch, replace the `DNS.pm` and `Config.pm` found wherever you're running INetSim with the files found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Then append the contents from `inetsim_patch.conf` to `/etc/inetsim/inetsim.conf`. Restart INetSim with `sudo systemctl restart inetsim.service`.

###### Geo-IP Service Patch

`HTTP.pm`

This file is located at `inetsim/geo_ip_service_patch/`. It allows an INetSim installation's HTTP service to return a fake response for a geo-IP service lookup.
In order to implement this patch, replace the `HTTP.pm` found wherever you're running INetSim with the file found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Restart INetSim with `sudo systemctl restart inetsim.service`.

#### Assemblyline System Safelist

##### CAPE-specific safelisted items

The file at `al_config/system_safelist.yaml` contains suggested safelisted values that can be added to the Assemblyline system safelist
either by copy-and-pasting directly to the text editor on the page `https://<Assemblyline Instance>/admin/tag_safelist` or through the [Assemblyline Client](https://github.com/CybercentreCanada/assemblyline_client).

#### Sources and prescript feature

By default the CAPE updater fetch the rules from the community and base repository. They are known as source from the service standpoint. If you do not wish to load them or to remove the community rules this need to be edited in the manifest under the 'update_config-->sources'.

!Beta! There is also a feature to run Yara rules on the sample prior to the analysis which is called prescript. They will be used to dictate preconfiguration of the virtual machine before the analysis. Details are going to be given when the prescript detection feature is officially release in CAPE. In order to run rules via this feature, a given source will need to have a `prescript_CAPE: true` the source's `configuration` setting.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| `Tag Type` | `Description`                                                                                  |      `Example Tag`       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name CAPE \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-cape

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service CAPE

Ce service Assemblyline soumet des fichiers à un déploiement CAPEv2 et analyse le rapport renvoyé.

## Détails du service
**NOTE** : Ce service **nécessite une installation supplémentaire importante en dehors d'Assemblyline** avant d'être fonctionnel. Il n'est **pas** préinstallé lors d'une installation par défaut.

Ce dépôt contient principalement du code adapté du [service Coucou d'Assemblyline].
[Assemblyline Cuckoo service] (https://github.com/CybercentreCanada/assemblyline-service-cuckoo), et
a été inspiré par le [projet](https://github.com/NVISOsecurity/assemblyline-service-cape)
créé par [x1mus](https://github.com/x1mus) avec le soutien de [Sorakurai](https://github.com/Sorakurai),
[jvanwilder](https://github.com/jvanwilder), et [RenaudFrere](https://github.com/RenaudFrere) à l'adresse suivante
[NVISOsecurity](https://github.com/NVISOsecurity).

### Aperçu du bac à sable de la CAPE

[CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) est une branche du projet open-source [Cuckoo Sandbox](https://cuckoosandbox.org). L'objectif de CAPE est d'ajouter le déballage automatisé des logiciels malveillants et l'extraction de la configuration. C'est aussi le dernier repo basé sur Cuckoo qui est maintenu et supporté.

### Aperçu du service CAPE d'Assemblyline

Le service CAPE utilise l'API REST CAPE pour envoyer des fichiers au nid CAPE qui distribue ensuite ces tâches à un ensemble de machines victimes (un fichier par victime).

`Vous êtes responsable de la configuration du nid CAPE et des victimes`. Les résultats de l'analyse pour la détonation d'un fichier soumis dans une victime sont ensuite récupérés,
et une version résumée du rapport est affichée à l'utilisateur par l'intermédiaire de l'interface utilisateur d'Assemblyline. Le rapport complet est également inclus dans l'interface utilisateur d'Assemblyline en tant que fichier supplémentaire pour votre plaisir de lecture.
Les fichiers qui sont décompressés et sauvegardés sur disque sont réinjectés dans Assemblyline.

### Choses à noter

#### Rapport

Il faut noter que ce service récupère le format `lite` du paquet de rapports. Assurez-vous donc d'avoir activé `litereport` dans votre fichier `reporting.conf` sur votre instance CAPE comme suit :

```
[litereport]
enabled = yes
keys_to_copy = info debug signatures network curtain sysmon target
behavior_keys_to_copy = processtree process summary
```

#### API REST

Certaines fonctionnalités de l'API utilisées par ce service sont désactivées sur l'instance publique de la CAPE. Ce service ne fonctionnera donc qu'avec un déploiement privé de la CAPE.

Puisque l'API RESTv2 est la seule version de l'API qui est [prise en charge] (https://capev2.readthedocs.io/en/latest/usage/api.html), nous ne prendrons en charge que cette version.

Puisque le service CAPE fera plus de 5 requêtes par minute, la configuration `api.conf` suivante est nécessaire pour l'API REST sur l'hôte CAPE :

```
[api]
ratelimit = no
default_user_ratelimit = 99999999999999/s
default_subscription_ratelimit = 99999999999999/s
token_auth_enabled = yes
```

Les appels à l'API REST effectués par le service CAPE sont les suivants :

1. Obtenir le statut de l'ACEP via GET /apiv2/cuckoo/status/.
2. Obtenir la liste des machines via GET /apiv2/machines/list/.
3. Rechercher le SHA256 d'un échantillon via GET /apiv2/tasks/search/sha256/\<sha256\>/
4. Soumettre un échantillon à une analyse de fichier via POST /apiv2/tasks/create/file/
5. Interroger la tâche par son ID jusqu'à ce qu'elle soit terminée via GET /apiv2/tasks/view/\<task-id\>/
6. Obtenir le rapport JSON allégé et le ZIP généré via GET /apiv2/tasks/get/report/\<task-id\>/lite/zip/
7. Supprimer la tâche via GET /apiv2/tasks/delete/\<task-id\>/

Par défaut dans le fichier `api.conf`, `[machinelist]`, `[cuckoostatus]`, et `[taskdelete]` sont tous désactivés. Vous devez les activer.

Dans `api.conf`, il est recommandé de mettre `token_auth_enabled = yes` et `auth_only = yes` pour tous les services de l'API REST.

#### Recommandations pour le contrôle

Le service CAPE soumet un fichier et attend que le fichier soit analysé et traité après l'analyse, jusqu'à ce que le délai d'attente du service soit de 800 secondes. À ce moment-là, le service réessaie (deux fois de plus) d'obtenir un résultat. Dans la plupart des cas, la seule raison pour laquelle le service réessaie est qu'il y a un problème avec le nid de la CAPE. Le service CAPE produit des journaux d'erreurs utiles sur lesquels vous pouvez configurer des alertes Kibana pour les cas où l'API REST de la CAPE ou les services de traitement sont en panne ou en erreur. Il s'agit de l'approche recommandée pour surveiller votre nid CAPE.

#### Options de service

##### Configurations de l'hôte

- `remote_host_details` : Une liste d'objets JSON, où chaque objet JSON représente un hôte de l'ACEP. Les détails concernant l'API de l'ACEP peuvent être trouvés [ici] (https://capev2.readthedocs.io/en/latest/usage/api.html). Chaque objet JSON doit avoir les clés et les valeurs suivantes :
  - `ip` - [default : 127.0.0.1] L'adresse IP de la machine où l'API CAPE est servie.
  - `port` - [default : 8000] Le port où l'API de l'ACEP est servie.
  - `api_key` - [default : sample_api_token] Le jeton d'authentification à transmettre lors de chaque appel à l'API.
  - `internet_connected` - [default : false] Un drapeau qui indique si l'hôte a la capacité d'acheminer vers Internet les appels réseau effectués par un fichier détonant.
  - `inetsim_connected` - [default : false] Un drapeau qui indique si l'hôte a la possibilité d'acheminer les appels réseau effectués par le fichier détoné vers INetSim.

##### Délais et tentatives de l'API REST

- `connection_timeout_in_seconds` - [default : 30] Délai d'attente utilisé pour effectuer la requête initiale auprès d'un hôte. (GET /machines/list)
- `rest_timeout_in_seconds` - [default : 120] Le délai utilisé pour effectuer les requêtes suivantes à un hôte. (GET /cuckoo/status/, POST /tasks/create/file/, GET /tasks/view/123/, GET /tasks/report/123/, DELETE /tasks/delete/123/, etc.)
- `connection_attempts` - [default : 3] Le nombre de tentatives pour se connecter (effectuer un GET /machines/list/) à un hôte.

##### Utilisez-vous UWSGI avec des travailleurs de recyclage ?

- `uwsgi_with_recycle` \N - [default : False] Cette configuration permet d'indiquer si l'API REST du nid CAPE avec laquelle nous allons interagir est hébergée par UWSGI ET si UWSGI a une configuration activée qui permet de recycler ses travailleurs. C'est la configuration recommandée car l'utilisation de CAPE avec le service par défaut cape-web.service (à partir du 6 septembre 2022) expose à une fuite de mémoire ().
  fuite de mémoire (https://github.com/kevoreilly/CAPEv2/issues/1112). Si vous avez activé UWSGI avec le recyclage des travailleurs, nous verrons fréquemment les erreurs "RemoteDisconnected" et "ConnectionResetError", nous allons donc faire taire les erreurs qui y sont associées.

Pour installer UWSGI : https://capev2.readthedocs.io/en/latest/usage/web.html?#best-practices-for-production

##### Configurations des victimes

- `allowed_images` : Une liste de chaînes représentant les images qui peuvent être sélectionnées pour la détonation.
- `auto_architecture` : Un objet JSON composé de la structure suivante :

```
    win :
        x64 : []
        x86 : []
    ub :
        x64 : []
        x86 : []
```

Ceci n'est pertinent que si vous utilisez la valeur `auto` pour le paramètre de soumission `specific_image`.

Si vous avez plusieurs images auxquelles un échantillon peut être envoyé pour détonation en fonction du type (par exemple Win7x64, Win10x64, Win7x86, Win10x86, WinXP et Win7x64WithOffice), mais que vous souhaitez qu'un échantillon ne soit envoyé qu'à un ensemble de ces images (par exemple, Win7x64 et Win10x64), vous pouvez alors spécifier ces images ici.

La méthode d'interprétation de cette structure est que les fichiers sont répartis entre Linux (ub) et Windows (win), ainsi que le processeur sur lequel ils doivent être exécutés (x86 ou x64). Si un fichier répond à ces conditions, il sera envoyé à toutes les images spécifiées dans la liste correspondante. Si un fichier ne remplit aucune de ces conditions, la liste par défaut est win + x64.

##### Configurations de l'analyse

- `default_analysis_timeout_in_seconds` - [default : 150] Le délai maximum pour une analyse.
- `max_dll_exports_exec` - [défaut : 5] Limite la quantité de DLL exécutées dont nous rendons compte.
- `machinery_supports_memory_dumps` - [défaut : False] Indicateur booléen indiquant si la machine CAPE prend en charge le dumping de la mémoire.
- `reboot_supported` - [default : False] Indicateur booléen indiquant si les machines de l'ACPE prennent en charge les soumissions de redémarrage. NB_ : La prise en charge du redémarrage n'est pas disponible d'emblée pour l'ACEP.
- `extract_cape_dumps` - [default : False] L'ACEP extrait beaucoup de choses. Certains diront "TROP". Activez ce paramètre si vous voulez que les fichiers qui sont téléchargés dans les répertoires `CAPE` et `procdump` par analyse soient extraits par Assemblyline. Notez que vous devez toujours sélectionner "deep_scan" après l'activation de ce paramètre si vous voulez tous les dumps CAPE, sinon le service choisira les dumps à extraire.
- `uses_https_proxy_in_sandbox` - [default : False] Indicateur booléen indiquant si l'architecture du bac à sable utilise un proxy HTTPS pour déchiffrer et transmettre le trafic.
- `suspicious_accepted_languages` - [default : []] Il s'agit d'une liste de langues dans l'en-tête HTTP "Accepted-Language" qui devraient être signalées comme suspectes.

##### Configurations des rapports

- `recursion_limit` - [default : 10000] Limite de récursivité de l'environnement Python dans lequel le service est exécuté. Cette limite est utilisée pour parcourir les grands JSON générés par l'analyse.

##### Spécifications INetSim

- `random_ip_range` - [default : 192.0.2.0/24] Il s'agit de la plage d'adresses IP qu'INetSim (s'il est configuré) choisira afin de renvoyer une adresse IP aléatoire pour toute requête DNS effectuée par les victimes (notez que cela nécessite un correctif d'INetSim). Cette option est principalement utilisée pour les listes de sécurité.
  NB : cette fonctionnalité repose sur la section "INetSim - Random DNS Resolution" ci-dessous.
- `inetsim_dns_servers` - [default : []] Il s'agit d'une liste d'IP de serveurs DNS INetSim.

##### Configurations des jetons de l'API

- `token_key` - [default : Token] C'est le mot-clé par défaut pour le Rest Framework de Django.
  Si vous le changez dans l'API REST de l'ACEP, changez cette valeur pour refléter cette nouvelle valeur.

##### Si la machine souhaitée n'est pas présente dans la configuration, dormir et réessayer ?

- `retry_on_no_machine` - [default : False] Si votre machine CAPE supprime des machines (AWS/Azure), il est possible qu'une certaine machine ne soit pas présente pendant un certain temps.
  pendant un certain temps. Cette configuration lèvera une RecoverableError dans cette situation, après avoir dormi pendant une certaine période de temps.
  période de temps.

##### Trop de journaux de surveillance ?

- `limit_monitor_apis` - [default : False] Applique une limite de 1000 aux APIs que le moniteur CAPE enregistre.

##### Devrions-nous configurer la VM avant l'exécution de l'échantillon en ouvrant quelques applications ?

Notez que ceci n'est applicable qu'aux échantillons qui utiliseraient les paquets `doc` et `js` normalement.

- `use_antivm_packages` - [default : False] Démarrer quelques applications avant l'exécution.

##### Vous voulez ajouter vos propres valeurs `processtree_id` à la volée ?

- `custom_processtree_id_safelist` - [default : list()] Une liste de `processtree_id`s à mettre sur liste de sécurité.

##### Vous voulez mettre en cache les résultats de l'ACEP tous les jours parce que le système de l'ACEP ne change pas si souvent ?

- `update_period` - [default : 24] Période/intervalle (en heures) pendant laquelle les signatures/règles YARA/extracteurs de configuration sont mis à jour sur le nid de l'ACEP.

#### Options de soumission à l'ACEP

Les options disponibles pour les soumissions au service de l'ACEP via l'API REST ne sont pas des plus claires, mais l'[utilitaire de soumission] (https://capev2.readthedocs.io/en/latest/usage/submit.html#submission-utility) nous en donne un aperçu. Il s'agit des options que vous pouvez sélectionner par analyse sans avoir à aller sous le capot :

- `analysis_timeout_in_seconds` - [default : 0] Temps d'attente maximum pour que l'analyse se termine. NB : Le travail d'analyse peut se terminer plus
  plus vite que cela si le processus surveillé se termine. Si la valeur est 0, l'analyse utilisera par défaut la valeur du paramètre de service `default_analysis_timeout_in_seconds`.
- `specific_image` - [default : [auto, auto_all, all]] Liste des images disponibles et des options auxquelles envoyer le fichier (l'option sélectionnée est attachée comme `tag` à la tâche CAPE).
  - En termes de sélection d'une victime pour la détonation, cette option a la troisième priorité la plus élevée, mais elle est la plus populaire auprès des analystes.
  - Cette liste doit contenir toutes les images disponibles, ainsi que les trois options `auto`, `auto_all` et `all` :
    - La chaîne représentant une image disponible est un `tag` dans les machines telles que KVM, QEMU, etc. ou `pool_tag` dans les machines telles qu'Azure. Lorsque vous déclarez vos machines/ensembles d'échelle dans votre fichier de configuration de machines à la CAPE, vous pouvez inclure des détails spécifiques sur cette entrée dans le champ `tags`, tels que "win10", "winxp" ou "office2016". En incluant également ces éléments dans la liste "specific_image" du service CAPE Assemblyline, vous pouvez soumettre des fichiers directement à ces machines en fonction de l'étiquette.
    - `auto` sélectionnera automatiquement la ou les images sur lesquelles un fichier sera détoné, en fonction de son type de fichier. Si vous avez beaucoup d'images sur lesquelles un fichier peut être détoné, utilisez le paramètre de service `auto_architecture` pour être plus spécifique.
    - `auto_all` ignorera le paramètre de service `auto_architecture`, et enverra le fichier à toutes les images qui peuvent détoner le type de fichier.
    - `all` enverra le fichier à toutes les images dans `allowed_images`.
- `dll_function` - [default : ""] Spécifie la fonction DLL à exécuter sur la DLL.
- `dump_memory` - [default : false] Une valeur booléenne indiquant si nous voulons que la mémoire de l'analyse soit vidée et que les plugins de volatilité soient exécutés dessus. NB_ : C'est très lent !
- `force_sleepskip` - [default : true] Force un échantillon qui tente de dormir à se réveiller et à sauter la tentative de sommeil.
- `no_monitor` - [default : false] Exécute l'analyse sans injecter l'agent de surveillance CAPE. Cela équivaut à passer `--options free=yes` (voir [here](https://capev2.readthedocs.io/en/latest/usage/packages.html) pour plus d'informations).
- `simulate_user` - [default : true] Active la simulation de l'utilisateur.
- `reboot` - [default : false] un booléen indiquant si nous voulons qu'une analyse soit répétée mais dans un environnement simulé "redémarré". NB_ : La prise en charge du redémarrage n'est pas disponible d'emblée pour le CAPE. Il s'agit également d'une option de développement, car les utilisateurs peuvent la sélectionner sans comprendre à quoi elle sert et doubler ainsi le temps de traitement.
- `arguments` - [default : ""] arguments de ligne de commande à passer à l'échantillon analysé.
- `custom_options` - [default : ""] Options personnalisées à passer à la soumission CAPE.
- `clock` - [default : ""] Définit l'horloge de la machine virtuelle (format %m-%d-%Y %H:%M:%S).
- `package` - [default : ""] Le nom du package d'analyse avec lequel l'échantillon doit être exécuté, avec des options prêtes à l'emploi trouvées [ici] (https://capev2.readthedocs.io/en/latest/usage/packages.html).
- `specific_machine` - [default : ""] Le nom de la machine sur laquelle vous voulez exécuter l'échantillon.
  Utilisé pour le développement, lorsque vous voulez envoyer un fichier à une machine spécifique sur un hôte spécifique. Le format de la chaîne est "<host-ip>:<nom de la machine>" s'il existe plusieurs hôtes. S'il n'y a qu'un seul hôte, le format peut être "<host-ip>:<nom de la machine>" ou "<nom de la machine>".
  - Ce format a la plus haute priorité pour la sélection de la victime lors de la soumission d'un fichier.
- `platform` - [default : "none"] Si vous ne vous souciez pas de la version du système d'exploitation que vous obtenez, tant qu'elle correspond à la plateforme, utilisez ceci.
  - C'est la deuxième priorité pour la sélection de la victime lors de la soumission d'un fichier.
- `routing` - [default : "none"] Spécifie le type de routage à utiliser pour chaque analyse.
- `ignore_cape_cache` - [default : false] S'il y a actuellement une tâche pour le même fichier avec exactement les mêmes options de tâche en cours d'analyse à la CAPE, ce paramètre ignorera cette tâche et en soumettra une nouvelle. Dans le cas contraire, le service suivra la tâche en cours d'analyse.
- `password` - [default : ""] Le mot de passe du fichier protégé par un mot de passe que vous soumettez à la CAPE.
- `monitored_and_unmonitored` - [default : false] Ce paramètre de soumission soumettra deux tâches à l'ACEP, l'une avec le moniteur activé et l'autre avec le moniteur désactivé. À utiliser avec discernement, car il double la charge de travail de l'ACEP.

#### Déploiement du nid de la CAPE

Voir la documentation officielle : https://capev2.readthedocs.io/en/latest/installation/host/index.html

#### Déploiement de la victime de la CAPE

Voir la documentation officielle : https://capev2.readthedocs.io/en/latest/installation/guest/index.html

#### Utilisation des signatures communautaires

Selon la documentation officielle, `cuckoo community` peut être exécuté sur la machine Nest afin d'installer les signatures.

#### L'heuristique du service CAPE

L'heuristique du service détermine la notation du résultat et peut couvrir une variété de comportements. L'heuristique est
Les heuristiques sont mises en place pour les appels réseau, les signatures, etc. En ce qui concerne les signatures, nous avons regroupé les plus de 500 signatures dans des catégories où chaque catégorie est une heuristique.
catégories où chaque catégorie est une heuristique et est représentative des signatures qui tombent dans cette catégorie.

##### Notation

Les scores pour ces catégories sont basés sur la moyenne des sévérités des signatures (qui peuvent être trouvées dans le repo de la Communauté CAPE
sur Github) pour toutes les signatures de cette catégorie. Cette moyenne a ensuite été arrondie (vers le haut >= .5, vers le bas < .5) et appliquée à
à la carte d'intervalle suivante :

> &lt;= 1 : 100 (informatif)
>
> &gt ; 1 et &lt;= 2 : 500 (suspect)
>
> &gt ; 2 et &lt;= 4 : 1000 (très suspect)
>
> &gt ; 4 : 2000 (malveillant)

##### ID ATT&CK

Pour ces catégories, nous avons tenté d'attribuer des identifiants ATT&CK Mitre par défaut en examinant toutes les signatures d'une catégorie,
puis en prenant l'ensemble de toutes les ID ATT&CK pour ces signatures (appelées `ttp` dans le code de la signature), et si l'ensemble était une seule ID
cet identifiant deviendrait l'identifiant par défaut de la catégorie. Des progrès sont réalisés dans la recherche d'identifiants génériques pouvant s'appliquer de manière générale à toutes les signatures d'une catégorie lorsque la tactique ci-dessus est utilisée.
d'une catégorie lorsque la tactique ci-dessus ne fonctionne pas, de sorte qu'il existe des valeurs par défaut pour toutes les heuristiques.

##### INetSim

###### Résolution DNS aléatoire

`DNS.pm, Config.pm, inetsim_patch.conf`

Ces fichiers sont situés dans `inetsim/random_dns_patch/`. Ils permettent au service DNS d'une installation INetSim de renvoyer une IP aléatoire à partir d'une plage donnée pour les recherches DNS.
Afin d'implémenter ce patch, remplacez les fichiers `DNS.pm` et `Config.pm` trouvés là où vous exécutez INetSim par les fichiers trouvés dans ce répertoire. Si vous êtes sur une machine Linux, ils
Linux, ils pourraient se trouver dans `/usr/share/perl5/INetSim/`. Ajoutez ensuite le contenu de `inetsim_patch.conf` à `/etc/inetsim/inetsim.conf`. Redémarrez INetSim avec `sudo systemctl restart inetsim.service`.

###### Patch du service Geo-IP

`HTTP.pm`

Ce fichier est situé dans `inetsim/geo_ip_service_patch/`. Il permet au service HTTP d'une installation INetSim de renvoyer une fausse réponse pour une recherche de service géo-IP.
Afin d'implémenter ce patch, remplacez le fichier `HTTP.pm` qui se trouve à l'endroit où vous exécutez INetSim par le fichier qui se trouve dans ce répertoire. Si vous êtes sur une machine Linux, ils peuvent se trouver dans `/usr.pm`.
dans `/usr/share/perl5/INetSim/`. Redémarrez INetSim avec `sudo systemctl restart inetsim.service`.

#### Liste de sécurité des systèmes d'assemblage

##### Éléments de la liste de sécurité spécifiques à l'ACEP

Le fichier `al_config/system_safelist.yaml` contient des suggestions de valeurs de liste de sécurité qui peuvent être ajoutées à la liste de sécurité du système Assemblyline
soit par copier-coller directement dans l'éditeur de texte de la page `https://<Assemblyline Instance>/admin/tag_safelist`, soit par l'intermédiaire du [Assemblyline Client] (https://github.com/CybercentreCanada/assemblyline_client).

#### Sources et fonction prescript

Par défaut, l'outil de mise à jour de l'ACEP récupère les règles dans le référentiel de la communauté et de la base. Ces règles sont appelées "sources" du point de vue du service. Si vous ne souhaitez pas les charger ou si vous souhaitez supprimer les règles communautaires, vous devez modifier le manifeste dans 'update_config-->sources'.

!Beta ! Il existe également une fonctionnalité permettant d'exécuter les règles de Yara sur l'échantillon avant l'analyse, appelée prescript. Elles seront utilisées pour dicter la préconfiguration de la machine virtuelle avant l'analyse. Des détails seront donnés lorsque la fonction de détection des prescripts sera officiellement lancée dans la CAPE. Afin d'exécuter des règles via cette fonctionnalité, une source donnée devra avoir un paramètre `prescript_CAPE : true` dans la `configuration` de la source.


## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| `Type d'étiquette` | `Description`                                                                                                |  `Exemple d'étiquette`   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name CAPE \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-cape

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
