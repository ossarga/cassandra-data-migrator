#!/bin/bash

set -euo pipefail

IFS=$'\n'
ERR_MSG=""

# Catch when we are about to exit and display the error.
trap "trap_exit" EXIT


info() {
  echo "INFO  [entrypoint] $1"
}


error() {
  echo "ERROR [entrypoint] $1" >&2
}


error_exit() {
  [ "$#" -gt 0 ] && ERR_MSG="$1"
  exit 1
}

trap_exit() {
  local rtn_code=$?
  local err_msg="$ERR_MSG"
  local err_msg_out=""

  if [ $rtn_code -eq 0  ]
  then
      return 0
  fi

  if [ -n "$err_msg" ]
  then
    err_msg_out="$err_msg. "
  fi

  if [ "$(cut -d' ' -f1 <<<"$BASH_COMMAND")" = "exit" ]
  then
    err_msg_out="${err_msg_out}Failed"
  else
    err_msg_out="${err_msg_out}Command '$BASH_COMMAND' failed"
  fi

  error "$err_msg_out with exit code $rtn_code."
}

set_cluster_role_credentials() {
  local cluster_role="$1"
  local credentials_user=""
  local cred_properties=("username" "password")

  eval "credentials_user=\${CDM_CREDENTIALS_${cluster_role}_JSON:-}"
  [ -z "$credentials_user" ] && return
  [ ! -f "$credentials_user" ] && \
    error_exit "Unable to find credentials file $credentials_user specified in CDM_CREDENTIALS_${cluster_role}_JSON"

  info "Reading credentials from $credentials_user for $cluster_role cluster"

  for prop_i in ${cred_properties[*]}
  do
    eval "env_cdm_connect_val=\${CDM_PROPERTY_SPARK_CDM_CONNECT_${cluster_role}_${prop_i^^}:-}"

    if [ -z "$env_cdm_connect_val" ]
    then
      cred_prop_val=$(jq -r ".${prop_i}" <"${credentials_user}")
      set_operating_file_values \
        "$CDM_PROPERTIES_FILE" \
        "env:SPARK_CDM_CONNECT_${cluster_role}_${prop_i^^}=${cred_prop_val}" \
        ""
    fi
  done
}

set_credentials() {
  local cluster_roles=("TARGET" "ORIGIN")

  for role_i in ${cluster_roles[*]}
  do
    set_cluster_role_credentials "$role_i"
  done
}

set_operating_file_values() {
  local file_path="$1"
  local env_var_op="$2"
  local delimiter_global="$3"
  local delimiter_regex_match="([[:space:]]+)"
  local delimiter_regex_replace="\2"
  local delimiter="$delimiter_global"
  local env_config_values=()
  local env_var_op_prefix=""
  local env_var_prefix=""
  local conf_val_regex_match=".*"

  env_var_op_prefix=$(cut -d':' -f1 <<<"$env_var_op")
  case "$env_var_op_prefix" in
  "env")
    env_config_values=("${env_var_op/env:/}")
    ;;
  "prefix")
    env_var_prefix="${env_var_op/prefix:/}"
    env_config_values=("$(env | grep "${env_var_prefix}" || echo '')")

    if [ "${#env_config_values[@]}" -eq 0 ] || [ -z "${env_config_values[*]}" ]
    then
      info "No environment variables with prefix '${env_var_prefix}' found; using default property values in $file_path"
      return 0
    fi
    ;;
  "*")
    error_exit "Unrecognised environment variable operation '$env_var_op_prefix'"
    ;;
  esac

  info "Updating settings in $file_path"
  for env_var in ${env_config_values[*]}
  do
    if [ -n "$delimiter_global" ]
    then
      delimiter_regex_match="([[:space:]]*${delimiter_global}[[:space:]]*)"
      delimiter="$delimiter_global"
    else
      delimiter_regex_match="([[:space:]]+)"
      delimiter=" "
    fi

    env_var_key=$(cut -d'=' -f1 <<<"${env_var/$env_var_prefix/}")
    conf_key=$(tr '_' '.' <<<"${env_var_key,,}")
    conf_val_new=${env_var/${env_var_prefix}${env_var_key}=/}

    temp_conf_val=""
    if [ "${conf_val_new:0:4}" = "env:" ]
    then
        eval "temp_conf_val=\$$(cut -d':' -f2 <<<"$conf_val_new")"
        conf_val_new="$temp_conf_val"
    fi

    # Use true to catch the case where the conf_key is not found in the file, otherwise grep will return a non-zero
    # exit code and cause the container to exit without a useful error message.
    conf_line=$(grep -i -E "^[#]?${conf_key}(${delimiter_regex_match}|$)" "$file_path" || true)
    if [ -z "$conf_line" ]
    then
      error_exit "Unable to find property $conf_key in $file_path"
    fi

    if [ "${conf_line:0:1}" == "#" ]
    then
      info_msg=" - Enabling"
    else
      info_msg=" - Updating"
    fi

    # Check if the line contains spaces and a value after the property key. If there is no space and value, then remove
    # the delimiter matching and set the delimiter replacement to four spaces.
    if [ "$(tr -s ' ' <<<"$conf_line" | cut -d"$delimiter" -f2 | tr -d ' ')" = "$conf_line" ]
    then
      delimiter_regex_match=""
      delimiter_regex_replace="    "
      conf_val_regex_match="$"
    else
      delimiter_regex_replace="\2"
      conf_val_regex_match=".*"
    fi

    info_msg="$info_msg property $conf_key"

    # perform a case insensitive search and replace as the conf_key is all lower case and the CDM Properties file
    # contains camel case properties.
    sed -i -E "s;^[#]?(${conf_key})${delimiter_regex_match}${conf_val_regex_match};\1${delimiter_regex_replace}${conf_val_new};i" "$file_path"

    info "${info_msg}"

  done
}

set_configuration_properties() {
  info "Reading CDM configuration properties from environment variables"
  set_operating_file_values "$CDM_PROPERTIES_FILE" "prefix:CDM_PROPERTY_" ""

  info "Reading log4j configuration properties from environment variables"
  set_operating_file_values "$CDM_LOG4J_CONFIGURATION" "prefix:CDM_LOGGING_" "="
}

import_ssl_certificates() {
    ssl_store_settings=${CMD_SSL_STORE_SETTINGS_JSON:-}
    [ -z "$ssl_store_settings" ] && return
    [ ! -f "$ssl_store_settings" ] && \
      error_exit "Unable to find SSL store settings file $ssl_store_settings specified in CMD_SSL_STORE_SETTINGS_JSON"

    info "Importing SSL certificate settings from $ssl_store_settings"

    local alias_val=""
    local file_val=""
    local keystore_val=""
    local storepass_val=""
    local cert_settings_list=()

    mapfile -t cert_settings_list < <(jq -r 'keys[]' <"$ssl_store_settings")

    for cert_set in ${cert_settings_list[*]}
    do
      for property_name in "alias" "file" "keystore" "storepass"
      do
        eval "${property_name}_val=$(jq -r ".${cert_set}.${property_name}" <"$ssl_store_settings")"
      done

      keytool \
        -import \
        -trustcacerts \
        -alias "$alias_val" \
        -noprompt \
        -file "$file_val" \
        -keystore "$keystore_val" \
        -storepass "$storepass_val"
    done
}

#--- main --------------------------------------------------------------------------------------------------------------

cdm_run_msg=""
cdm_spark_job=""

if [ "$CDM_EXECUTION_MODE" = "auto" ]
then
  case "${CDM_JOB_NAME,,}" in
    migrate)
      cdm_spark_job="Migrate"
      ;;
    validate|diffdata)
      cdm_spark_job="DiffData"
      ;;
    guardrail|guardrailcheck)
      cdm_spark_job="GuardrailCheck"
      ;;
    *)
      error_exit "Unrecognised job name '$CDM_JOB_NAME'. Valid job names are: 'migrate', 'validate', or 'guardrail'."
      ;;
  esac

  cdm_run_msg="Running ${cdm_spark_job} job using the following command."
elif [ "$CDM_EXECUTION_MODE" = "manual" ]
then
  cdm_run_msg="Run"
  alternative_word=" "

  if [ -n "$CDM_JOB_NAME" ]
  then
    cdm_run_msg="${cdm_run_msg} 'spark-submit-cdm' to launch the '$CDM_JOB_NAME' job, or run"
    alternative_word=" different "
  fi

  cdm_run_msg="${cdm_run_msg} 'spark-submit-cdm <job>' to launch a${alternative_word}CDM job."
else
  error_exit "Unrecognised execution mode '$CDM_EXECUTION_MODE'. Please specify either 'auto' or 'manual'."
fi

info "Setting up Cassandra Data Migrator $CDM_VERSION"
info "Using Java $JAVA_VERSION"
info "Using Spark $SPARK_VERSION"
info "Using Scala $SCALA_VERSION"

set_credentials
set_configuration_properties
import_ssl_certificates

info "Cassandra Data Migrator configured successfully. ${cdm_run_msg}"

if [ "$CDM_EXECUTION_MODE" = "auto" ]
then
  exec_cmd=(
    spark-submit
    --driver-java-options "-Dlog4j.configuration=file:$CDM_LOG4J_CONFIGURATION -Dvm.logging.level=$CDM_VM_LOGGING_LEVEL"
    --properties-file "$CDM_PROPERTIES_FILE"
    --master local[*]
    --driver-memory "$CDM_DRIVER_MEMORY"
    --executor-memory "$CDM_EXECUTOR_MEMORY"
    --class com.datastax.cdm.job."${cdm_spark_job}"
    /opt/cassandra-data-migrator/cassandra-data-migrator.jar
  )
  info "$(tr -s '\n' ' ' <<<"${exec_cmd[@]}")"
  sleep 7
  exec "${exec_cmd[@]}"
else
  exec tail -f /dev/null
fi
