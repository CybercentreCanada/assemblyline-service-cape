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

**You are responsible for setting up the CAPE nest and victims**. The analysis results for the detonation of a submitted file in a victim is then retrieved,
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

For more information on how to configure this service, click [here](./configuration.md).

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

**Vous êtes responsable de la configuration du nid CAPE et des victimes**. Les résultats de l'analyse pour la détonation d'un fichier soumis dans une victime sont ensuite récupérés,
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

Pour plus d'informations sur la configuration de ce service, cliquez [ici](./configuration.md).

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
