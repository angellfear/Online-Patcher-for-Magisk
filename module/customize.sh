# Runs during module install (Magisk app or `magisk --install-module`).
# The install zip is built on Windows (PowerShell's Compress-Archive doesn't
# store Unix permission bits at all), so every file lands here as plain 644
# regardless of what it was before zipping - explicitly fix executable bits
# rather than relying on the zip to have carried them.

set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/bin/patcher 0 0 0755
set_perm $MODPATH/post-fs-data.sh 0 0 0755
set_perm $MODPATH/service.sh 0 0 0755
