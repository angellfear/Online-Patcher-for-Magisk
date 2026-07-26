#!/system/bin/sh
# All paths are derived by the binary itself from its own location; the
# config URL comes from the "config_url" file next to it (or from state, if
# the server has since redirected it) - nothing is hardcoded. This wrapper
# only exists because Magisk needs a .sh file to hook late_start service at
# all; the binary itself owns the poll loop (daemon mode never returns).
nohup ${0%/*}/bin/patcher daemon >/dev/null 2>&1 &
