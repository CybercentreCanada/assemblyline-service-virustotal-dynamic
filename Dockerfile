ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH virustotal_dynamic.VirusTotalDynamic

USER root
RUN pip install vt-py

# Switch to assemblyline user
USER assemblyline

# Copy VirusTotalDynamic service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline