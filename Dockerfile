FROM eclipse-temurin:11-jammy

ENV SPARK_VERSION=3.4.2
ENV CDM_VERSION=4.1.12

# Install Spark
WORKDIR /install

ENV SPARK_HOME=/opt/spark

RUN curl -OL https://archive.apache.org/dist/spark/spark-${SPARK_VERSION}/spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz && \
    tar -xzf ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz && \
    mv ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13 $SPARK_HOME && \
    rm ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz

ENV PATH=$PATH:${SPARK_HOME}/bin

# Install Python 3.9
WORKDIR /usr/bin

RUN apt-get update && \
    apt-get install -y jq software-properties-common vim && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.9 && \
    unlink python3 && \
    ln -s python3.9 python3

# Install CDM and configuration files
WORKDIR /opt/cassandra-data-migrator

RUN curl -OL https://github.com/datastax/cassandra-data-migrator/releases/download/${CDM_VERSION}/cassandra-data-migrator-${CDM_VERSION}.jar && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm.properties && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/cdm-detailed.properties && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/partitions.csv && \
    curl -OL https://raw.githubusercontent.com/datastax/cassandra-data-migrator/${CDM_VERSION}/src/resources/primary_key_rows.csv && \
    ln -s cassandra-data-migrator-${CDM_VERSION}.jar cassandra-data-migrator.jar

ENV CDM_JAR=/opt/cassandra-data-migrator/cassandra-data-migrator.jar \
    CDM_PROPERTIES=/opt/cassandra-data-migrator/cdm.properties \
    CDM_DETAILED_PROPERTIES=/opt/cassandra-data-migrator/cdm-detailed.properties \
    CDM_PARTITIONS_CSV=/opt/cassandra-data-migrator/partitions.csv \
    CDM_PRIMARY_KEY_ROWS_CSV=/opt/cassandra-data-migrator/primary_key_rows.csv

ENV CDM_DEFAULT_PROPERTIES=$CDM_DETAILED_PROPERTIES

RUN mkdir -p /var/log/cassandra-data-migrator

# Set up logging
ENV CDM_LOGGING=/var/log/cassandra-data-migrator \
    CDM_LOGGING_LEVEL=INFO \
    CDM_LOGGING_OUTPUT=file

ENV CDM_DRIVER_MEMORY=25G \
    CDM_EXECUTOR_MEMORY=25G

COPY entrypoint.sh spark-submit-cdm /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/spark-submit-cdm

ENTRYPOINT ["entrypoint.sh"]
CMD [""]