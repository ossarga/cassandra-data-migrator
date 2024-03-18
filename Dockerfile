FROM eclipse-temurin:17-jammy

ENV CDM_VERSION=4.1.12 \
    SPARK_VERSION=3.4.2 \
    SCALA_VERSION=2.13.12 \
    ZOOKEEPER_VERSION=3.8.3 \
    SNAKEYAML_VERSION=2.0

# Install Spark
WORKDIR /install

ENV SPARK_HOME=/opt/spark

RUN curl -OL https://archive.apache.org/dist/spark/spark-${SPARK_VERSION}/spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz && \
    tar -xzf ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz && \
    mv ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13 $SPARK_HOME && \
    rm ./spark-${SPARK_VERSION}-bin-hadoop3-scala2.13.tgz

# The following libraries packaged with Spark have critical vulnerabilities, so upgrade to a new version or remove them
#  - scala-library 2.13.8 -> upgrade
#  - scala-compiler 2.13.8 -> upgrade
#  - jackson-mapper-asl 1.9.13 -> remove
#  - derby 10.14.2.0 -> remove
#  - zookeeper 3.6.3 -> upgrade
#  - snakeyaml 1.33 -> upgrade
RUN curl -OL https://downloads.lightbend.com/scala/${SCALA_VERSION}/scala-${SCALA_VERSION}.tgz && \
    tar -xzf ./scala-${SCALA_VERSION}.tgz && \
    rm ${SPARK_HOME}/jars/scala-library-*.jar && \
    rm ${SPARK_HOME}/jars/scala-compiler-*.jar && \
    cp ./scala-${SCALA_VERSION}/lib/scala-library.jar ${SPARK_HOME}/jars/scala-library-${SCALA_VERSION}.jar && \
    cp ./scala-${SCALA_VERSION}/lib/scala-compiler.jar ${SPARK_HOME}/jars/scala-compiler-${SCALA_VERSION}.jar && \
    rm -r ./scala-${SCALA_VERSION} && \
    rm ./scala-${SCALA_VERSION}.tgz

RUN rm ${SPARK_HOME}/jars/jackson-mapper-asl-*.jar

RUN rm ${SPARK_HOME}/jars/derby-*.jar

RUN curl -OL https://repo1.maven.org/maven2/org/apache/zookeeper/zookeeper/${ZOOKEEPER_VERSION}/zookeeper-${ZOOKEEPER_VERSION}.jar && \
    curl -OL https://repo1.maven.org/maven2/org/apache/zookeeper/zookeeper-jute/${ZOOKEEPER_VERSION}/zookeeper-jute-${ZOOKEEPER_VERSION}.jar && \
    rm ${SPARK_HOME}/jars/zookeeper-*.jar && \
    mv ./zookeeper-${ZOOKEEPER_VERSION}.jar ${SPARK_HOME}/jars/zookeeper-${ZOOKEEPER_VERSION}.jar && \
    mv ./zookeeper-jute-${ZOOKEEPER_VERSION}.jar ${SPARK_HOME}/jars/zookeeper-jute-${ZOOKEEPER_VERSION}.jar

RUN curl -OL https://repo1.maven.org/maven2/org/yaml/snakeyaml/${SNAKEYAML_VERSION}/snakeyaml-${SNAKEYAML_VERSION}.jar && \
    rm ${SPARK_HOME}/jars/snakeyaml-*.jar && \
    mv ./snakeyaml-${SNAKEYAML_VERSION}.jar ${SPARK_HOME}/jars/snakeyaml-${SNAKEYAML_VERSION}.jar

ENV PATH=$PATH:${SPARK_HOME}/bin

# Install Python 3.9 and jq
WORKDIR /usr/bin

RUN apt-get update && \
    apt-get install -y jq software-properties-common vim && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y jq python3.9 && \
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
    CDM_CREDENTIALS_TARGET_JSON="" \
    CDM_CREDENTIALS_ORIGIN_JSON="" \
    CMD_SSL_STORE_SETTINGS_JSON=""

COPY entrypoint.sh spark-submit-cdm /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/spark-submit-cdm

ENTRYPOINT ["entrypoint.sh"]
CMD [""]