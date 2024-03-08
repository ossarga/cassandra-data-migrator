#!/bin/bash

set -euo pipefail

# Sets what to do after entrypoint has completed all its operations. By default we will wait indefinitely after we have
# completed all the operations in the entrypoint.
COMPLETION_ACTION="wait"
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


set_operating_file_values() {
  local file_path="$1"
  local env_var_prefix="$2"
  local delimiter="$3"
  local delimiter_regex_match="[\ ]+"
  local delimiter_regex_replace="\2"

  env_config_values=("$(env | grep "$env_var_prefix" || echo '')")

  if [ "${#env_config_values[@]}" -eq 0 ] || [ -z "${env_config_values[*]}" ]
  then
    info "No environment variables with prefix '$env_var_prefix' found; using default property values in $file_path"
    return 0
  fi

  if [ -n "$delimiter" ]
  then
    delimiter_regex_match="[\ ]*${delimiter}[\ ]*"
  else
    delimiter=" "
  fi

  info "Updating settings in $file_path"
  for env_var in ${env_config_values[*]}
  do
    env_var_key=$(cut -d'=' -f1 <<<"${env_var/$env_var_prefix/}")
    conf_key=$(tr '[:upper:]' '[:lower:]' <<<"$env_var_key" | tr '_' '.')
    new_conf_val=${env_var/${env_var_prefix}${env_var_key}=/}

    temp_conf_val=""
    if [ "${new_conf_val:0:4}" = "env:" ]
    then
        eval "temp_conf_val=\$$(cut -d':' -f2 <<<"$new_conf_val")"
        new_conf_val="$temp_conf_val"
    fi

    # Use true to catch the case where the conf_key is not found in the file, otherwise grep will return a non-zero
    # exit code and cause the container to exit without a useful error message.
    conf_line=$(grep -i -e "^[#]*${conf_key}" "$file_path" || true)
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
    # the delimiter matching and set the delimiter replacement to eight spaces.
    if [ "$(tr -s ' ' <<<"$conf_line" | cut -d"$delimiter" -f2 | tr -d ' ')" = "$conf_line" ]
    then
      delimiter_regex_match=""
      delimiter_regex_replace="        "
    fi

    info_msg="$info_msg property $conf_key"

    # perform a case insensitive search and replace as the conf_key is all lower case and the CDM Properties file
    # contains camel case properties.
    sed -i -E "s;^[#]?($conf_key)($delimiter_regex_match).*;\1${delimiter_regex_replace}${new_conf_val};i" "$file_path"

    info "${info_msg}"

    done
}

# Have the option to override the default completion behaviour incase we want to run the entrypoint manually from
# within the container.
[ "$#" -gt 0 ] && COMPLETION_ACTION="$1"

info "Setting up Cassandra Data Migrator $CDM_VERSION"
info "Using Java $JAVA_VERSION"
info "Using Spark $SPARK_VERSION"
info "Using Scala $SCALA_VERSION"

set_operating_file_values "$CDM_PROPERTIES_FILE" "CDM_PROPERTY_" ""
set_operating_file_values "$CDM_LOG4J_CONFIGURATION" "CDM_LOGGING_" "="

info "Ready to run Cassandra Data Migrator. Run spark-submit-cdm to start the migration."

if [ "$COMPLETION_ACTION" = "exit" ]
then
  exit 0
fi

tail -f /dev/null