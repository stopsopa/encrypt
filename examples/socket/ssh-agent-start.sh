#
# Makes sure the private demo ssh-agent of examples/socket is running.
# Can be called again and again: when the agent already runs nothing is started, the script
# only reports it and ends with exit code 0.
#
# The agent is a second, separate ssh-agent only for this example. Your own agent is never
# asked and never changed: every command here names the private socket explicitly.
#
# What it creates, both in examples/socket/tmp/ (ignored by git):
#   agent.sock   the socket file the agent listens on; programs talk to the agent through it
#   agent.env    the two shell lines ssh-agent printed when it started (SSH_AUTH_SOCK=…,
#                SSH_AGENT_PID=…); ssh-agent-stop.sh reads the pid from it
#
# Usage (from any directory):
#
#   /bin/bash examples/socket/ssh-agent-start.sh
#
# A script cannot change the environment of the terminal that called it, so to make ssh-add
# and ssenc of your terminal use this agent, run this yourself afterwards (the script prints
# the line with the full path):
#
#   export SSH_AUTH_SOCK="$PWD/examples/socket/tmp/agent.sock"
#
# The agent starts empty. Load a key with: ssh-add examples/socket/tmp/key
# Stop it with: /bin/bash examples/socket/ssh-agent-stop.sh
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

# The path of a unix socket is limited (104 bytes on macOS, 108 on Linux).
if [[ "${#SOCK}" -gt 100 ]]; then
  echo "${0} error: the socket path is too long (${#SOCK} characters, at most 100), move the repository to a shorter path, SOCK=>${SOCK}<"
  exit 1
fi

mkdir -p "${TMP}"

# ssh-add -l exits with 2 when it cannot reach an agent, with 0 or 1 when one answers
# (0: it holds keys, 1: it holds none).
SSH_AUTH_SOCK="${SOCK}" ssh-add -l >/dev/null 2>&1
if [[ "${?}" != "2" ]]; then
  cat <<EEE
ssh-agent already running, nothing started
  socket: ${SOCK}
  export SSH_AUTH_SOCK="${SOCK}"
EEE
  exit 0
fi

# Nobody answers: a socket file that is still there was left by an agent that died.
rm -f "${SOCK}" "${ENVFILE}"

if ! ssh-agent -a "${SOCK}" > "${ENVFILE}"; then
  rm -f "${ENVFILE}"
  echo "${0} error: ssh-agent could not be started on SOCK=>${SOCK}<"
  exit 1
fi

cat <<EEE
ssh-agent started
  socket: ${SOCK}
  pid:    $(grep -o 'SSH_AGENT_PID=[0-9]*' "${ENVFILE}" | cut -d = -f 2)
  export SSH_AUTH_SOCK="${SOCK}"
EEE
