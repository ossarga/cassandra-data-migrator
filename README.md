# cassandra-data-migrator

A Docker image for [Cassandra Data Migrator (CDM)](https://github.com/datastax/cassandra-data-migrator), designed to be run by a container orchestrator.

---

## About

This project packages the [DataStax Cassandra Data Migrator](https://github.com/datastax/cassandra-data-migrator) and [Apache Spark](https://spark.apache.org/) into a hardened, production-ready container image.

The image supports three CDM jobs:

| Job | Description |
|---|---|
| `migrate` | Migrates data from an origin Cassandra cluster to a target cluster. |
| `validate` | Compares data between origin and target clusters, reporting differences. |
| `guardrail` | Checks that data in the origin cluster meets guardrail constraints before migration. |

The build pipeline is security-focused. It uses [Trivy](https://trivy.dev/) to scan the initial image for vulnerabilities, then automatically patches both Spark JAR dependencies and Alpine OS packages before producing the final image.

---

## Prerequisites

- [Podman](https://podman.io/) (used by the build script)
- [Trivy](https://trivy.dev/) (used by the build script for vulnerability scanning)
- A GitHub personal access token (PAT) with `read:packages` permission — required to download the CDM JAR from the [GitHub Package Registry](https://github.com/datastax/cassandra-data-migrator/packages)

---

## GitHub Authentication

The build requires a GitHub PAT to download the CDM JAR. Create a file named `.github-auth` in the repository root with your credentials in `user:token` format:

```
your-github-username:ghp_your_personal_access_token
```

> **Note:** `.github-auth` is listed in `.gitignore` and will not be committed.

---

## Building the Image

### Default Mode — Build, Scan, and Patch

The standard workflow builds the image, scans it with Trivy to identify vulnerable dependencies, then rebuilds with the generated patches applied.

```bash
./build-image.sh
```

This performs the following steps:

1. Builds an initial image (downloading Spark and the CDM JAR).
2. Scans the image with Trivy and saves the report to `reports/<tag>/unpatched-image-vulnerabilities-report.json`.
3. Copies the Trivy report to `patch-reports-upload/` so the Dockerfile can consume it.
4. Rebuilds the image, applying JAR dependency upgrades and OS package updates derived from the Trivy report.
5. Scans the patched image and saves the report to `reports/<tag>/patched-image-vulnerabilities-report.json`.
6. Creates and pushes a multi-architecture manifest to `docker.io/ossarga/cassandra-data-migrator`.
7. Copies the remediation reports (`spark-jar-remediation.txt`, `os-remediation.txt`) out of the container into `reports/<tag>/`.

### Patch Directory Mode — Skip the Initial Build

If you already have patch files from a previous build (or have authored them manually), you can skip the initial build and Trivy scan:

```bash
./build-image.sh --patch-dir <path-to-patch-directory>
```

The patch directory must contain both:

- `spark-jar-patch.json` — JAR dependency upgrades to apply to the Spark package.
- `os-package-patch.json` — Alpine OS package upgrades to apply to the final image.

Example using the included sample patch directory:

```bash
./build-image.sh --patch-dir ./patch-reports-upload/6.1.0.1-dev.20260928
```

---

## Build Options

### Supplying Spark via a Local Archive

By default the Dockerfile downloads Spark from the Apache CDN at build time. If network access is restricted or you want to pin a specific archive, place the Spark `.tgz` file in the `spark-package-upload/` directory before building.

The file must match the naming convention used by the Apache Spark distribution:

```
spark-<SPARK_VERSION>-bin-hadoop3.tgz
```

For example, for Spark 4.2.0:

```
spark-package-upload/spark-4.2.0-bin-hadoop3.tgz
```

When the file is present, the Dockerfile skips the download step and uses the local archive instead.

### Supplying Patch Files via a Directory

Instead of running an initial Trivy scan, you can provide pre-generated patch files using the `--patch-dir` flag (see [Patch Directory Mode](#patch-directory-mode--skip-the-initial-build) above).

Patch files placed in a subdirectory of `patch-reports-upload/` are automatically available to the Dockerfile. The two required files are:

| File | Purpose |
|---|---|
| `spark-jar-patch.json` | Specifies JAR upgrades to apply inside the Spark `jars/` directory. |
| `os-package-patch.json` | Specifies Alpine OS package upgrades to apply in the final image layer. |

Any additional files present in the directory (e.g. remediation reports) are also copied into the image under `/opt/cassandra-data-migrator/build-artefacts/`.

See [`spark-update-dependencies-example.json`](./spark-update-dependencies-example.json) for the patch file format.

### Supplying a Trivy Report Directly

The Dockerfile also accepts a Trivy JSON report via the `TRIVY_REPORT_FILENAME_ARG` build argument. This is handled automatically by `build-image.sh` in the default build mode — you do not normally need to set this manually.

If you do invoke `podman build` directly, place the Trivy report in `patch-reports-upload/` and pass its filename:

```bash
podman build \
  --secret id=github_auth,src=.github-auth \
  --build-arg TRIVY_REPORT_FILENAME_ARG="my-trivy-report.json" \
  --tag cassandra-data-migrator:local \
  .
```

---

## Build Arguments

The following `--build-arg` values are accepted by the `Dockerfile`:

| Argument | Default | Description |
|---|---|---|
| `CDM_VERSION_ARG` | `6.1.0` | Version of the CDM JAR to download. |
| `SPARK_VERSION_ARG` | `4.2.0` | Version of Apache Spark to download or use from `spark-package-upload/`. |
| `TRIVY_REPORT_FILENAME_ARG` | _(empty)_ | Filename of a Trivy JSON report placed in `patch-reports-upload/`. Mutually exclusive with `PATCH_DIRECTORY_ARG`. |
| `PATCH_DIRECTORY_ARG` | _(empty)_ | Name of a subdirectory inside `patch-reports-upload/` containing pre-generated `spark-jar-patch.json` and `os-package-patch.json`. Mutually exclusive with `TRIVY_REPORT_FILENAME_ARG`. |

---

## Running the Container

The image is configured via environment variables and a CDM properties file.

### Execution Modes

The `CDM_EXECUTION_MODE` environment variable controls how the container starts:

| Mode | Behaviour |
|---|---|
| `auto` _(default)_ | Applies configuration, then immediately launches the Spark job specified by `CDM_JOB_NAME`. |
| `manual` | Applies configuration and then keeps the container running. Use `spark-submit-cdm <job>` inside the container to launch a job on demand. |

### Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CDM_EXECUTION_MODE` | `auto` | Execution mode (`auto` or `manual`). |
| `CDM_JOB_NAME` | `migrate` | Job to run in `auto` mode (`migrate`, `validate`, or `guardrail`). |
| `CDM_DRIVER_MEMORY` | `25G` | Spark driver memory. |
| `CDM_EXECUTOR_MEMORY` | `25G` | Spark executor memory. |
| `CDM_PROPERTIES_FILE` | `$CDM_DETAILED_PROPERTIES` | Path to the CDM properties file used at runtime. |
| `CDM_CREDENTIALS_TARGET_JSON` | _(empty)_ | Path to a JSON file containing `username` and `password` for the target cluster. |
| `CDM_CREDENTIALS_ORIGIN_JSON` | _(empty)_ | Path to a JSON file containing `username` and `password` for the origin cluster. |
| `CMD_SSL_STORE_SETTINGS_JSON` | _(empty)_ | Path to a JSON file containing SSL keystore settings. |
| `CDM_LOG4J_CONFIGURATION` | `$CDM_LOG4J_PROPERTIES` | Path to the log4j configuration file (`log4j.properties` or `log4j.xml`). |
| `CDM_VM_LOGGING_LEVEL` | `WARN` | JVM logging level passed to log4j. |

CDM properties can also be set via environment variables prefixed with `CDM_PROPERTY_`. Each variable is mapped to the corresponding CDM property key (underscores converted to dots, lowercased). For example:

```bash
CDM_PROPERTY_SPARK_CDM_CONNECT_ORIGIN_HOST=cassandra-origin.example.com
```

sets the CDM property `spark.cdm.connect.origin.host`.

Log4j properties can be overridden with variables prefixed `CDM_LOGGING_`.

### Example: Running a Migration (auto mode)

```bash
podman run \
  --rm \
  -v /path/to/cdm-detailed.properties:/opt/cassandra-data-migrator/cdm-detailed.properties:ro \
  -e CDM_JOB_NAME=migrate \
  docker.io/ossarga/cassandra-data-migrator:<tag>
```

### Example: Running in Manual Mode

```bash
podman run \
  -d \
  --name cdm \
  -v /path/to/cdm-detailed.properties:/opt/cassandra-data-migrator/cdm-detailed.properties:ro \
  -e CDM_EXECUTION_MODE=manual \
  docker.io/ossarga/cassandra-data-migrator:<tag>

# Then exec in and run a job:
podman exec -it cdm spark-submit-cdm migrate
```

---

## Image Layout

| Path | Description |
|---|---|
| `/opt/cassandra-data-migrator/` | CDM JAR, properties files, log4j config, and build artefacts. |
| `/opt/spark/` | Apache Spark installation (`$SPARK_HOME`). |
| `/var/log/cassandra-data-migrator/` | Default log output directory. |
| `/usr/local/bin/entrypoint.sh` | Container entrypoint — configures CDM and launches Spark. |
| `/usr/local/bin/spark-submit-cdm` | Helper script to submit a CDM Spark job by name. |

---

## Repository Structure

| Path | Description |
|---|---|
| `Dockerfile` | Multi-stage build: download binaries → patch dependencies → final image. |
| `build-image.sh` | Build, scan, and push script. |
| `entrypoint.sh` | Container entrypoint script. |
| `spark-submit-cdm` | Spark job launcher script installed into the image. |
| `build-tools/` | Python scripts used during the build to parse Trivy reports and update JARs/OS packages. |
| `spark-package-upload/` | Drop a local Spark `.tgz` here to avoid downloading it at build time. |
| `patch-reports-upload/` | Drop a Trivy JSON report or a pre-generated patch directory here before building. |
| `reports/` | Build output: Trivy scan results and remediation reports, organised by image tag. |
| `log4j.properties` / `log4j.xml` | Log4j configuration files bundled into the image. |

---

## License

See [LICENSE](./LICENSE).
