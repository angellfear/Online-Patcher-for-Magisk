# Runs during module install (Magisk app or `magisk --install-module`).
# The install zip is built on Windows (PowerShell's Compress-Archive doesn't
# store Unix permission bits at all), so every file lands here as plain 644
# regardless of what it was before zipping - explicitly fix executable bits
# rather than relying on the zip to have carried them.

# The server URL lives in the module's config_url file (baked in at build
# time from config_url.txt in the repo root). If present, report it.
if [ -s "$MODPATH/config_url" ]; then
  ui_print "- config_url: $(cat "$MODPATH/config_url")"
else
  ui_print "- config_url not set; create $MODPATH/config_url before first boot"
fi

set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/bin/patcher 0 0 0755
set_perm $MODPATH/post-fs-data.sh 0 0 0755
set_perm $MODPATH/service.sh 0 0 0755
set_perm $MODPATH/config_url 0 0 0644
