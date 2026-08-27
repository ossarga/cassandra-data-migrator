ARG CDM_VERSION_ARG=6.1.0
ARG SPARK_VERSION_ARG=4.2.0

ARG TRIVY_REPORT_FILENAME_ARG=trivy-image-report.json
ARG SPARK_JAR_PATCH_FILENAME_ARG=""

# --- Stage 1: Download Spark and Cassandra Data Migrator ---
FROM debian:bookworm-slim AS download-binaries

ARG CDM_VERSION_ARG
ARG SPARK_VERSION_ARG

ENV CDM_VERSION=${CDM_VERSION_ARG}
ENV SPARK_VERSION=${SPARK_VERSION_ARG}

WORKDIR /download

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY ./spark-package-upload/ ./

RUN SPARK_PACKAGE=spark-${SPARK_VERSION}-bin-hadoop3 && \
    if [ ! -f "./${SPARK_PACKAGE}.tgz" ]; then \
        curl -OL "https://dlcdn.apache.org/spark/spark-${SPARK_VERSION}/${SPARK_PACKAGE}.tgz"; \
    fi

RUN SPARK_PACKAGE=spark-${SPARK_VERSION}-bin-hadoop3 && \
    tar -xzf ./${SPARK_PACKAGE}.tgz && \
    mv ./${SPARK_PACKAGE} ./spark-package && \
    rm ./${SPARK_PACKAGE}.tgz

RUN --mount=type=secret,id=github_auth \
    GITHUB_AUTH=$(cat /run/secrets/github_auth) && \
    mkdir -p ./cassandra-data-migrator-bin && \
    curl \
        --fail \
        -u "${GITHUB_AUTH}" \
        -L \
        -o "cassandra-data-migrator-${CDM_VERSION}.jar" \
        "https://maven.pkg.github.com/datastax/cassandra-data-migrator/datastax/cdm/cassandra-data-migrator/${CDM_VERSION}/cassandra-data-migrator-${CDM_VERSION}.jar" && \
    test "$(stat -c%s cassandra-data-migrator-${CDM_VERSION}.jar)" -gt 10000000 && \
    curl --fail -OL "https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm.properties" && \
    curl --fail -OL "https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm-detailed.properties" && \
    mv cassandra-data-migrator-${CDM_VERSION}.jar cdm.properties cdm-detailed.properties ./cassandra-data-migrator-bin


# --- Stage 2: Update Dependencies ---
FROM python:3.12-slim-bookworm AS update-packages

ARG TRIVY_REPORT_FILENAME_ARG
ARG SPARK_JAR_PATCH_FILENAME_ARG

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /update

COPY --from=download-binaries /download/spark-package ./spark-package
COPY ./build-tools ./build-tools
COPY ./patch-reports-upload ./patch-reports-upload

RUN PATCHING_SKIPPED_MSG="No image report supplied; skipping image patching" && \
    mkdir ./build-artefacts && \
    if [ -z "${TRIVY_REPORT_FILENAME_ARG}" ]; then \
        echo "${PATCHING_SKIPPED_MSG}"; \
        echo "${PATCHING_SKIPPED_MSG}" > ./build-artefacts/spark-jar-remediation.txt && \
        echo "${PATCHING_SKIPPED_MSG}" > ./build-artefacts/os-remediation.txt; \
    elif [ -f "./patch-reports-upload/${TRIVY_REPORT_FILENAME_ARG}" ]; then \
        echo "Image report supplied; patching image..." && \
        ./build-tools/parse-vulnerabilities.py \
            ./patch-reports-upload/${TRIVY_REPORT_FILENAME_ARG} \
            ./build-artefacts/spark-jar-patch.json \
            ./build-artefacts/spark-jar-remediation.txt \
            ./build-artefacts/os-patch.json \
            ./build-artefacts/os-remediation.txt \
            --resolve-direct \
            --resolve-indirect \
            --skip-prefixes spark- cassandra-data-migrator && \
        if [ -n "${SPARK_JAR_PATCH_FILENAME_ARG}" ] && [ -f "./patch-reports-upload/${SPARK_JAR_PATCH_FILENAME_ARG}" ]; then \
            rm ./build-artefacts/spark-jar-patch.json && \
            cp "./patch-reports-upload/${SPARK_JAR_PATCH_FILENAME_ARG}" ./build-artefacts/spark-jar-patch.json; \
        fi && \
        ./build-tools/update-jar-dependencies.py ./build-artefacts/spark-jar-patch.json ./spark-package/jars && \
        ./build-tools/update-os-packages.py ./build-artefacts/os-patch.json ./build-artefacts/os-package-updates.sh; \
    else \
        echo "Error: Unable to find image report ${TRIVY_REPORT_FILENAME_ARG}; aborting build!"; \
        exit 1; \
    fi

# --- Stage 3: Install Spark and Cassandra Data Migrator ---
FROM eclipse-temurin:17-jre-alpine AS cdm-final

ARG CDM_VERSION_ARG
ARG SPARK_VERSION_ARG

# Install Spark
ENV SPARK_HOME=/opt/spark
ENV SPARK_VERSION=${SPARK_VERSION_ARG}

WORKDIR ${SPARK_HOME}

COPY --from=update-packages /update/spark-package ./

ENV PATH="${SPARK_HOME}/bin:${PATH}"

# Install Cassandra Data Migrator
ENV CDM_HOME=/opt/cassandra-data-migrator
ENV CDM_VERSION=${CDM_VERSION_ARG}

WORKDIR ${CDM_HOME}

COPY --from=download-binaries /download/cassandra-data-migrator-bin ./

ENV CDM_JAR=/opt/cassandra-data-migrator/cassandra-data-migrator.jar \
    CDM_PROPERTIES=/opt/cassandra-data-migrator/cdm.properties \
    CDM_DETAILED_PROPERTIES=/opt/cassandra-data-migrator/cdm-detailed.properties

ENV CDM_PROPERTIES_FILE=$CDM_DETAILED_PROPERTIES

# Set up logging
COPY log4j.properties log4j.xml ./

ENV CDM_LOG_DIR=/var/log/cassandra-data-migrator/ \
    CDM_VM_LOGGING_LEVEL=WARN \
    CDM_LOG4J_PROPERTIES=/opt/cassandra-data-migrator/log4j.properties \
    CDM_LOG4J_XML=/opt/cassandra-data-migrator/log4j.xml

ENV CDM_LOG4J_CONFIGURATION=$CDM_LOG4J_PROPERTIES

# Spark environment variables
ENV CDM_DRIVER_MEMORY=25G \
    CDM_EXECUTOR_MEMORY=25G

ENV CDM_EXECUTION_MODE=auto \
    CDM_JOB_NAME=migrate \
    CDM_CREDENTIALS_TARGET_JSON="" \
    CDM_CREDENTIALS_ORIGIN_JSON="" \
    CMD_SSL_STORE_SETTINGS_JSON=""

# Install entrypoint and dependencies

COPY entrypoint.sh spark-submit-cdm /usr/local/bin/
# build-artefacts/ content varies depending on the build stage:
#   First image build (no report): contains only placeholder .txt files; os-package-updates.sh absent.
#   Second image build (report supplied): contains patch JSONs, remediation reports, and os-package-updates.sh.
COPY --from=update-packages /update/build-artefacts ./build-artefacts

RUN apk add --no-cache bash jq && \
    if [ -f ./build-artefacts/os-package-updates.sh ]; then \
        chmod 755 ./build-artefacts/os-package-updates.sh && \
        ./build-artefacts/os-package-updates.sh; \
    fi && \
    java -version && \
    bash --version && \
    jq --version && \
    ln -s cassandra-data-migrator-${CDM_VERSION}.jar cassandra-data-migrator.jar && \
    mkdir -p /var/log/cassandra-data-migrator && \
    chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/spark-submit-cdm

ENTRYPOINT ["entrypoint.sh"]
CMD []