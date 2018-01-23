#!/bin/bash
#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
# 
# This program attempts to publish updated documentation to our gh-pages
# branch.
# 
# We read the .version file from ../.version.
# 
# The docs are published into the gh-pages branch, in a directory
# called man/v<version>.
# 
# This script requires asciidoctor, pygments, git, and a UNIX shell.
# 

tmpdir=$(mktemp -d)
srcdir=$(dirname $0)
dstdir=${tmpdir}/pages
cd ${srcdir}
vers=$(cat ../.version)
dstman=${dstdir}/man/v${vers}
name=nng

giturl="${GITURL:-git@github.com:nanomsg/nng}"

cleanup() {
	echo "DELETING ${tmpdir}"
	rm -rf ${tmpdir}
}

mkdir -p ${tmpdir}

trap cleanup 0

echo git clone ${giturl} ${dstdir} || exit 1
git clone ${giturl} ${dstdir} || exit 1

(cd ${dstdir}; git checkout gh-pages)

[ -d ${dstman} ] || mkdir -p ${dstman}

dirty=
for input in $(find . -name '*.adoc'); do
	adoc=${input#./}
	html=${adoc%.adoc}.html
	output=${dstman}/${html}

	status=$(git status -s $input )
	when=$(git log -n1 --format='%ad' '--date=format-local:%s' $input )
	cat <<EOF > ${output}
---
version: ${vers}
layout: default
---
EOF

	if [ -n "$when" ]
	then
		epoch="SOURCE_DATE_EPOCH=${when}"
	else
		epoch=
		dirty=yes
	fi
	if [ -n "$status" ]
	then
		echo "File $adoc is not checked in!"
		dirty=yes
	fi


	env ${epoch} asciidoctor \
		-aversion-label=${name} \
		-arevnumber=${vers}  \
		-askip-front-matter \
		-asource-highlighter=pygments \
		-aicons=font \
		-bhtml5 \
		-o - ${adoc} >> ${output}
	chmod 0644 ${output}

	if [ $? -ne 0 ]
	then
		echo "Failed to process $adoc !"
		fails=yes
	fi
		

	(cd ${dstman}; git add ${html})
done

if [ -n "$dirty" ]
then
	echo "Repository has uncommited documentation.  Aborting."
	exit 1
fi

if [ -n "$fails" ]
then
	echo "Failures formatting documentation. Aborting."
	exit 1
fi

(cd ${dstman}; git commit -m "man page updates for ${vers}"; git push origin gh-pages)
