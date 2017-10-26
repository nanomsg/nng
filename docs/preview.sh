#!/bin/bash
#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# This script is used to preview in HTML or man format, the documentation.
# I use it during development, YMMV.  It is probably completely useless
# on Windows.

case $(uname -s) in
Darwin)
	OPEN=open
	MAN=man
	;;
Linux)
	OPEN=xdg-open
	MAN=man
	;;
*)
	echo "No idea how to preview on this system."
	exit 2
esac

if [[ -n "$DISPLAY" ]]
then
	style=html
else
	style=man
fi

while getopts hmc arg
do
	case "${arg}" in
	h)	style=html;;
	m)	style=man;;
	c)	cleanup=yes;;
	?)	echo "Usage: $0 [-h|-m] <files...>"; exit 1 ;;
	esac
done
shift $(( $OPTIND - 1 ))

open_man=${MAN}
open_html=${OPEN}
suffix_html=".html"
suffix_man=".man"
backend_html="html5"
backend_man="manpage"
version=$(cat $(dirname $0)/../.version)
name=nng

if [ -n "${cleanup}" ]
then
	tempdir=$(mktemp -d)
	clean() {
		rm -rf ${tempdir}
	}
	trap clean 0
	mkdir -p ${tempdir}
else
	tempdir=/tmp/${LOGNAME}.${name}.preview
	mkdir -p ${tempdir}
fi

eval backend=\$backend_${style}
eval suffix=\$suffix_${style}
eval view=\$open_${style}

for input in "$@"; do
	base=$(basename $input)
	base=${base%.adoc}
	output=${tempdir}/${base}${suffix}
	asciidoctor -aversion-label=${name} -arevnumber=${version} \
		-b ${backend} -o ${output} $input
	$view $output
	sleep 1
done
