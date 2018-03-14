#!/bin/ksh
#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
MANMANUAL="NNG Reference Manual"
MANSOURCE="NNG"
LAYOUT=refman
name=nng


TIPVERS=$(cd ${srcdir}; git describe --always origin/master)
GITVERS=$(cd ${srcdir}; git describe --always)

if [[ -z "${VERSION}" ]]
then
	if [[ "${GITVERS}" == *-* ]]
	then
		if [[ "${GITVERS}" == "${TIPVERS}" ]]
		then
			VERSION=tip
		else
			printf "Cannot publish - sources not pushed yet.\n"
			exit 1
		fi
	else
		VERSION="${GITVERS}"
	fi
fi

printf "PUBLISHING version ${VERSION}\n"

if [ ${VERSION} == tip ]
then
	dstman=${dstdir}/man/tip
else
	dstman=${dstdir}/man/v${VERSION}
fi

giturl="${GITURL:-git@github.com:nanomsg/nng}"

cleanup() {
	printf "DELETING ${tmpdir}\n"
	rm -rf ${tmpdir}
}

getinfo() {
	PAGE=
	SECT=
	DESC=

	while read line
	do
		case "$line" in
		"//"*)
			;;
		"= "**|"="*)
			if [ -z "${PAGE}" ] && [ -z "${SECT}" ]
			then
				PAGE=${line%\(}
				PAGE=${PAGE#=}
				PAGE=${PAGE## }
				PAGE=${PAGE%\(*}
				SECT=${line#*\(}
				SECT=${SECT%\)}
			fi
			;;

		*" - "*)
			if [ -z "${DESC}" ] && [ -n "${PAGE}" ] && [ -n "${SECT}" ]
			then
				DESC=${line#*- }
				return
			fi
			;;
		esac
	done
}

mkdir -p ${tmpdir}

trap cleanup 0

typeset -A descs
typeset -A pages
echo git clone ${giturl} ${dstdir} || exit 1
git clone ${giturl} ${dstdir} || exit 1

(cd ${dstdir}; git checkout gh-pages)

[ -d ${dstman} ] || mkdir -p ${dstman}

dirty=
files=( $(find . -name '*.adoc' -print | sort ) )

printf "Processing files: [%3d%%]" 0
typeset -i num
typeset -i pct

num=0
pct=0
for input in ${files[@]}
do 
	num=$(( num + 1 ))
	pct=$(( num * 100 / ${#files[@]} ))

	printf "\b\b\b\b\b\b[%3d%%]" ${pct}
	adoc=${input#./}
	html=${adoc%.adoc}.html
	output=${dstman}/${html}

	status=$(git status -s $input )
	when=$(git log -n1 --format='%ad' '--date=format-local:%s' $input )
	cat <<EOF > ${output}
---
version: ${VERSION}
layout: ${LAYOUT}
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
		printf "\nFile $adoc is not checked in!\n"
		dirty=yes
	fi

	getinfo < ${adoc}
	if [ -n "${DESC}" ]
	then
		descs[${PAGE}_${SECT}]="$DESC"
		pages[${SECT}]=( ${pages[$SECT][*]} $PAGE )
	fi

	 env ${epoch} asciidoctor \
		-dmanpage \
		-amansource="${MANSOURCE}" \
		-amanmanual="${MANMANUAL}" \
		-anofooter=yes \
		-askip-front-matter \
		-atoc=left \
		-asource-highlighter=pygments \
		-aicons=font \
		-bhtml5 \
		-o - ${adoc} >> ${output}
	chmod 0644 ${output}

	if [ $? -ne 0 ]
	then
		printf "\n$Failed to process $adoc !\n"
		fails=yes
	fi

	(cd ${dstman}; git add ${html})
done

printf "\nProcessing index: "

index=${dstman}/index.asc

cat <<EOF > ${index}
= NNG Reference Manual: ${VERSION}

The following pages are present:

EOF

typeset -A titles
titles[1]="Utilities and Programs"
titles[3]="Library Functions"
titles[5]="Macros and Types"
titles[7]="Protocols and Transports"

for S in $(echo ${!pages[@]} | sort )
do
	printf "\n== Section ${S}: ${titles[$S]}\n"

	printf "\n[cols=\"3,5\"]\n"
	printf "|===\n"
	for P in $(echo ${pages[$S][@]} | tr " " "\n" | sort)
	do
		printf "|<<${P}#,${P}(${S})>>\n"
		printf "|${descs[${P}_${S}]}\n"
		printf "\n"
	done
	printf "|===\n"
done >> ${index}

cat <<EOF >${dstman}/index.html
---
version: ${VERSION}
layout: ${LAYOUT}
---
EOF

env ${epoch} asciidoctor \
	-darticle \
	-anofooter=yes \
	-askip-front-matter \
	-atoc=left \
	-aicons=font \
	-bhtml5 \
	-o - ${index} >> ${dstman}/index.html
chmod 0644 ${dstman}/index.html

(cd ${dstman}; git add index.html)

if [ -n "$dirty" ]
then
	printf "Repository has uncommited documentation.  Aborting.\n"
	exit 1
fi

if [ -n "$fails" ]
then
	printf "\nFailures formatting documentation. Aborting.\n"
	exit 1
fi
printf "Done.\n"

(cd ${dstman}; git commit -m "man page updates for ${VERSION}"; git push origin gh-pages)
