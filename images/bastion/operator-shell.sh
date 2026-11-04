# shellcheck shell=sh
# operator-shell.sh: the bastion's login environment for the operator, installed as
# /etc/profile.d/sfab-operator.sh (login shells) and sourced from /etc/bash.bashrc (interactive
# shells). It sets nothing a script relies on: the harness runs kubectl through docker exec as
# root, which reads /root/.kube/config, the kubeconfig bastion-init.sh picks up.
#
# Interactive shells get the k alias with kubectl's completion and start in /workspace; a shell
# opened before the cluster published its kubeconfig says so once.
[ -n "${_SFAB_OPERATOR_SHELL:-}" ] && return 0 2>/dev/null
_SFAB_OPERATOR_SHELL=1
case ":${PATH}:" in *":/usr/local/bin:"*) : ;; *) PATH="/usr/local/bin:${PATH}"; export PATH ;; esac
case "$-" in
    *i*)
        if [ ! -s "${HOME:-/root}/.kube/config" ]; then
            printf 'no kubeconfig yet: the init node publishes it when the cluster bootstrap finishes\n' >&2
        fi
        if [ -n "${BASH_VERSION:-}" ] && command -v kubectl >/dev/null 2>&1; then
            alias k='kubectl'
            eval "$(kubectl completion bash 2>/dev/null)"
            # shellcheck disable=SC3044  # bash only: this branch runs only when BASH_VERSION is set
            complete -o default -F __start_kubectl k 2>/dev/null
        fi
        cd /workspace 2>/dev/null || true
        ;;
esac
