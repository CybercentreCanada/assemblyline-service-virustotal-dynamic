FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH virustotal_dynamic.VirusTotalDynamic

# Switch to assemblyline user
USER assemblyline

# Copy VirusTotalDynamic service code
WORKDIR /opt/al_service
COPY . .
