#!/system/bin/sh
# All paths are derived by the binary itself from its own location (see
# get_exe_dir()/get_module_dir() in patcher.c) - this wrapper only exists
# because Magisk needs a .sh file to hook post-fs-data at all. "boot" mode
# is fast (network-free instant-cache mount only), so it's safe to run
# synchronously this early in boot.
${0%/*}/bin/patcher boot
