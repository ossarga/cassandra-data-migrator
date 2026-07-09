ARG CDM_VERSION_ARG=6.0.1
ARG SPARK_VERSION_ARG=4.1.2

# --- Stage 1: Download and extract Spark ---
FROM debian:latest AS spark-download

ARG SPARK_VERSION_ARG
ENV SPARK_VERSION=${SPARK_VERSION_ARG}
ENV SPARK_PACKAGE=spark-${SPARK_VERSION}-bin-hadoop3

WORKDIR /download

COPY ./spark-package-source/ ./

RUN if [ ! -f "./${SPARK_PACKAGE}.tgz" ]; then \
        apt-get update && \
        apt-get install -y curl && \
        curl -OL "https://dlcdn.apache.org/spark/spark-${SPARK_VERSION}/${SPARK_PACKAGE}.tgz"; \
    fi

RUN tar -xzf ./${SPARK_PACKAGE}.tgz && \
    mv ./${SPARK_PACKAGE} ./spark-package

# --- Stage 2: Update Spark ---
FROM python:latest AS spark-update

WORKDIR /install

COPY --from=spark-download /download/spark-package ./spark-package

COPY update-dependencies.py spark-update-dependencies.json ./

RUN chmod 755 update-dependencies.py && \
    ./update-dependencies.py spark-update-dependencies.json ./spark-package/jars


# --- Stage 3: Install Spark and Cassandra Data Migrator---
FROM eclipse-temurin:17-jammy AS cdm-final

ARG CDM_VERSION_ARG
ARG SPARK_VERSION_ARG

# Install Spark
ENV SPARK_HOME=/opt/spark

COPY --from=spark-update /install/spark-package ${SPARK_HOME}

ENV PATH=$PATH:${SPARK_HOME}/bin

# Install CDM and configuration files
ENV CDM_VERSION=${CDM_VERSION_ARG}
ENV SPARK_VERSION=${SPARK_VERSION_ARG}

WORKDIR /opt/cassandra-data-migrator

RUN apt-get update && \
    apt-get install -y jq vim

RUN curl -OL https://github.com/datastax/cassandra-data-migrator/releases/download/${CDM_VERSION}/cassandra-data-migrator-${CDM_VERSION}.jar && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm.properties && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm-detailed.properties && \
    ln -s cassandra-data-migrator-${CDM_VERSION}.jar cassandra-data-migrator.jar

ENV CDM_JAR=/opt/cassandra-data-migrator/cassandra-data-migrator.jar \
    CDM_PROPERTIES=/opt/cassandra-data-migrator/cdm.properties \
    CDM_DETAILED_PROPERTIES=/opt/cassandra-data-migrator/cdm-detailed.properties

ENV CDM_PROPERTIES_FILE=$CDM_DETAILED_PROPERTIES

RUN mkdir -p /var/log/cassandra-data-migrator

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

COPY entrypoint.sh spark-submit-cdm /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/spark-submit-cdm

ENTRYPOINT ["entrypoint.sh"]
CMD [""]