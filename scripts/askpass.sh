#!/bin/sh
# Invoked by `sudo -A`, which passes its prompt as $1. zenity rejects a bare
# positional argument, so feed it in as the dialog body instead.
exec zenity --password --timeout=120 --title="fmmon" --text="$1"
