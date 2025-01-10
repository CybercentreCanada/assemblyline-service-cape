#!/bin/bash
set -euo pipefail

docker build \
    --pull \
    --build-arg branch=stable \
    -t ${PWD##*/}:pytest \
    -f ./Dockerfile \
    .

if [[ -n "$FULL_SAMPLES_LOCATION" ]]; then
    MOUNT_SAMPLES="-v ${FULL_SAMPLES_LOCATION}:/opt/samples"
    ENV_SAMPLES="-e FULL_SAMPLES_LOCATION=/opt/samples"
fi
docker run \
    -t \
    --rm \
    -e FULL_SELF_LOCATION=/opt/al_service \
    $ENV_SAMPLES \
    -v /usr/share/ca-certificates/mozilla:/usr/share/ca-certificates/mozilla \
    -v $(pwd)/tests/:/opt/al_service/tests/ \
    $MOUNT_SAMPLES \
    ${PWD##*/}:pytest \
    bash -c "pip install -U -r tests/requirements.txt; pytest -p no:cacheprovider --durations=10 -rsx -vv -x"
