#!/bin/bash

set -eEo pipefail

CDM_VERSION=6.1.0.1-dev
GIT_HASH=$(git rev-parse --short HEAD)
DATE_NOW=$(date "+%Y%m%d")

IMAGE_TAG="${CDM_VERSION}.${GIT_HASH}.${DATE_NOW}"
IMAGE_NAME=docker.io/ossarga/cassandra-data-migrator

DOWNLOAD_CONTAINER_NAME=""

EXIT_STATUS=0
FAILED_LINE=""
FAILED_CMD=""

cleanup() {
    if [ "${EXIT_STATUS}" -eq 0 ]
    then
        echo "Build successful!"
    else
        echo "Build failed!"
        if [ -n "${FAILED_LINE}" ]
        then
            echo "    Line Number: ${FAILED_LINE}"
        fi
        if [ -n "${FAILED_CMD}" ]
        then
            echo "    Command:     ${FAILED_CMD}"
        fi
        echo "    Exit Status: ${EXIT_STATUS}"
    fi

    if [ -f "/tmp/${IMAGE_TAG}.amd64.tar" ]
    then
        rm -f "/tmp/${IMAGE_TAG}.amd64.tar"
    fi

    if [ -n "${DOWNLOAD_CONTAINER_NAME}" ]
    then
        local container_status="$(podman inspect --format='{{.State.Status}}' ${DOWNLOAD_CONTAINER_NAME})" || true
        if [ "${container_status}" == "running" ]
        then
            echo -n "Stopping container: ${DOWNLOAD_CONTAINER_NAME} "
            podman stop "${DOWNLOAD_CONTAINER_NAME}" >/dev/null 2>&1 || true
            while [ "${container_status}" != "exited" ]
            do
                sleep 1
                container_status="$(podman inspect --format='{{.State.Status}}' ${DOWNLOAD_CONTAINER_NAME})" || true
            done
            echo "- Done"
        fi

        if [ "${container_status}" == "exited" ]
        then
            echo -n "Removing container: ${DOWNLOAD_CONTAINER_NAME} "
            podman rm "${DOWNLOAD_CONTAINER_NAME}" >/dev/null 2>&1 || true
            echo "- Done"
        fi
    fi

    exit "${EXIT_STATUS}"
}

check_image() {
    local patch_report_file_path="$1"

    podman save \
    --format docker-archive \
    -o "/tmp/${IMAGE_TAG}.amd64.tar" \
    "${IMAGE_NAME}:${IMAGE_TAG}.amd64"

    trivy image \
        --input "/tmp/${IMAGE_TAG}.amd64.tar" \
        -f json \
        -o "${patch_report_file_path}"

    rm -f "/tmp/${IMAGE_TAG}.amd64.tar"
}


trap 'cleanup' EXIT

trap 'EXIT_STATUS=$?; FAILED_LINE="$LINENO"; FAILED_CMD="$BASH_COMMAND"; exit $EXIT_STATUS' ERR

trap 'EXIT_STATUS=130; exit 130' SIGINT
trap 'EXIT_STATUS=143; exit 143' SIGTERM

echo "-------------------------------------------------------------------------"
echo "Image tag is: ${IMAGE_TAG}"
echo "-------------------------------------------------------------------------"
echo ":: Building image ::"
podman build \
    --secret id=github_auth,src=.github-auth \
    --pull=always \
    --no-cache \
    --platform linux/amd64 \
    --build-arg TRIVY_REPORT_FILENAME_ARG="" \
    --tag "${IMAGE_NAME}:${IMAGE_TAG}.amd64" \
    .

mkdir -p "./reports/${IMAGE_TAG}/"

echo "-------------------------------------------------------------------------"
echo ":: Checking image ::"
check_image "./reports/${IMAGE_TAG}/unpatched-image-vulnerabilities-report.json"
cp "./reports/${IMAGE_TAG}/unpatched-image-vulnerabilities-report.json" "./patch-reports-upload/trivy-report_${IMAGE_TAG}.amd64.json"

echo "-------------------------------------------------------------------------"
echo ":: Rebuilding image with patches ::"
podman build \
    --secret id=github_auth,src=.github-auth \
    --pull=never \
    --platform linux/amd64 \
    --build-arg TRIVY_REPORT_FILENAME_ARG="trivy-report_${IMAGE_TAG}.amd64.json" \
    --tag "${IMAGE_NAME}:${IMAGE_TAG}.amd64" \
    .

echo "-------------------------------------------------------------------------"
echo ":: Re-checking image ::"
check_image "./reports/${IMAGE_TAG}/patched-image-vulnerabilities-report.json"

echo "-------------------------------------------------------------------------"
echo ":: Creating manifest ::"
podman manifest create "${IMAGE_NAME}:${IMAGE_TAG}"
podman manifest add \
    "${IMAGE_NAME}:${IMAGE_TAG}" \
    "${IMAGE_NAME}:${IMAGE_TAG}.amd64"
echo "Pushing manifest to remote"
podman manifest push --all "${IMAGE_NAME}:${IMAGE_TAG}"

echo "-------------------------------------------------------------------------"
echo ":: Downloading vulnerability patching reports ::"
DOWNLOAD_CONTAINER_NAME="cmd-downloader-$(tr -s '.' '_' <<< ${CDM_VERSION})-${GIT_HASH}-${DATE_NOW}"

podman run \
    --detach \
    --name "${DOWNLOAD_CONTAINER_NAME}" \
    --env CDM_EXECUTION_MODE="manual" \
    "${IMAGE_NAME}:${IMAGE_TAG}.amd64"

WAIT_TIMEOUT=60
WAIT_ELAPSED=0
while [ "$(podman inspect --format='{{.State.Status}}' "${DOWNLOAD_CONTAINER_NAME}")" != "running" ]
do
    container_state="$(podman inspect --format='{{.State.Status}}' "${DOWNLOAD_CONTAINER_NAME}")"
    if [ "${container_state}" = "exited" ] || [ "${container_state}" = "dead" ]; then
        echo "Container '${DOWNLOAD_CONTAINER_NAME}' failed to start (state: ${container_state})"
        exit 1
    fi
    if [ "${WAIT_ELAPSED}" -ge "${WAIT_TIMEOUT}" ]; then
        echo "Timed out waiting for container '${DOWNLOAD_CONTAINER_NAME}' to reach running state"
        exit 1
    fi
    sleep 5
    WAIT_ELAPSED=$((WAIT_ELAPSED + 5))
done

podman cp \
    "${DOWNLOAD_CONTAINER_NAME}":/opt/cassandra-data-migrator/build-artefacts/. \
    "./reports/${IMAGE_TAG}/"
echo "-------------------------------------------------------------------------"
exit 0