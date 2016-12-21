#!/bin/sh

PATH=${PATH}:/opt/pkg/bin export PATH
stat=0
find src -name '*.[ch]' -print | while read file 
do
	uncrustify -c etc/uncrustify.cfg -lC -f $file | colordiff -u $file -
	if [ $? -ne 0 ]
	then
		stat=1
	fi
done

if [ $stat -ne 0 ]
then
	echo "Format errors detect.  Please fix."
	exit 1
fi
exit 0
