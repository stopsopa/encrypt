#
# Stops the private demo ssh-agent that examples/socket/ssh-agent-start.sh started and
# removes its two files (examples/socket/tmp/agent.sock and agent.env).
# Can be called again and again: when the agent does not run it only reports that and ends
# with exit code 0.
#
# Only that one agent is stopped: the pid is read from agent.env, and it is killed only when
# a process with that pid exists and is an ssh-agent. Your own agent is never touched.
#
# Usage (from any directory):
#
#   /bin/bash examples/socket/ssh-agent-stop.sh
#
# SSH_AUTH_SOCK of your terminal is not changed by this script (it cannot be). If you pointed
# it to the private agent, set it back yourself or open a new terminal.
#

_SHELL="$(ps -p $$ -o comm=)"; # bash || sh || zsh
_SHELL="$(basename "${_SHELL//-/}")"
case ${_SHELL} in
  zsh)
    # shellcheck disable=SC2296
    _DIR="$( cd "$( dirname "${(%):-%x}" )" && pwd -P )"
    ;;
  sh)
    _DIR="$( cd "$( dirname "${0}" )" && pwd -P )"
    ;;
  *)
    _DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P )"
    ;;
esac

TMP="${_DIR}/tmp"
SOCK="${TMP}/agent.sock"
ENVFILE="${TMP}/agent.env"

if [[ ! -f "${ENVFILE}" ]]; then
  rm -f "${SOCK}"
  echo "ssh-agent not running (no ${ENVFILE}), nothing to stop"
  exit 0
fi

PID="$(grep -o 'SSH_AGENT_PID=[0-9]*' "${ENVFILE}" | cut -d = -f 2)"

if [[ -z "${PID}" ]]; then
  echo "${0} error: no SSH_AGENT_PID found in ENVFILE=>${ENVFILE}<"
  exit 1
fi

# The pid could belong to another program by now (after a reboot): kill only an ssh-agent.
COMMAND="$(ps -p "${PID}" -o comm= 2>/dev/null)"

if [[ "${COMMAND}" == *ssh-agent* ]]; then
  if ! kill "${PID}"; then
    echo "${0} error: could not stop ssh-agent PID=>${PID}<"
    exit 1
  fi
  echo "ssh-agent stopped, pid ${PID}"
else
  echo "ssh-agent not running (pid ${PID} from ${ENVFILE} is gone), nothing to stop"
fi

rm -f "${SOCK}" "${ENVFILE}"
