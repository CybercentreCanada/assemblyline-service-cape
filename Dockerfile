ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH cape.cape_main.CAPE

USER root

# Get required apt packages
RUN apt-get update && apt-get install -y qemu-utils && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN bash -c "if [[ $branch == latest ]]; then \
    pip install --no-cache-dir --user --requirement requirements.txt --pre && rm -rf ~/.cache/pip; else \
    pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip; fi"

# Copy CAPE service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
