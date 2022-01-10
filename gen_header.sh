#!/bin/bash

OUI_FILE="oui.h"

gen_header()
{
	touch "$OUI_FILE"
	echo "static const char* __vendors[][2] = {" >> "$OUI_FILE"
	
	while read p; do
		echo "$p" | awk '{ print "{\042"$1"\042, \042"$2"\042}," }' >> "$OUI_FILE"
	done < oui
	
	echo -e "};\nstatic const unsigned int __vendors_size = `cat oui | wc -l`;" >> "$OUI_FILE"
}

if [ ! -f "$OUI_FILE" ]
then
	gen_header
fi
