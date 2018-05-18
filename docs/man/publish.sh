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

curdir=$(pwd)
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
	if [[ "${GITVERS}" == *-g??????? ]]
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

# strip leading v in v1.0.0
VERSION=${VERSION#v}
printf "PUBLISHING version ${VERSION}\n"

if [ "${VERSION}" == tip ]
then
	dstman=${dstdir}/man/tip
else
	dstman=${dstdir}/man/v${VERSION}
fi

giturl="${GITURL:-git@github.com:nanomsg/nng}"

cleanup() {
	cd $curdir
	printf "DELETING ${tmpdir}\n"
	rm -rf ${tmpdir}
}

getdesc() {
	typeset input=$1
	typeset -i doname=0

	while read line
	do
		case "$line" in
		"== NAME")
			doname=1
			;;
		==*)
			doname=0
			;;

		"//"*|"")
			;;

		*" - "*)
			if (( doname ))
			then
				echo ${line#*- }
				return
			fi
			;;
		esac
	done < $input
}

mkdir -p ${tmpdir}

trap cleanup 0

typeset -A descs
typeset -A pages
typeset -A htmls
echo git clone ${giturl} ${dstdir} || exit 1
git clone ${giturl} ${dstdir} || exit 1

(cd ${dstdir}; git checkout gh-pages)

[ -d ${dstman} ] || mkdir -p ${dstman}

dirty=
files=( $(find . -name '*.adoc' -print | sort ) )
status=$(git status -s *.adoc)
if [[ -n "${status}" ]]
then
	printf "Files not checked in!\n"
	git status -s *.adoc
	dirty=yes
fi


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
	adoc=${input#*/}
	base=${adoc%.adoc}
	html=${base}.html
	page=${base%.*}
	sect=${base##*.}
	output=${dstman}/${html}
	

	cat <<EOF > ${output}
---
version: ${VERSION}
layout: ${LAYOUT}
---
EOF

	if [[ -z "${sect}" ]]
	then
		printf "\nNo section in file name for ${adoc}!\n"
		fails=yes
	fi
	if [[ -z "${page}" ]]
	then
		printf "\nNo section topic for ${adoc}!\n"
		fails=yes
	fi

	desc=$(getdesc ${adoc})
	if [[ -n "${desc}" ]]
	then
		descs[${page}_${sect}]="$desc"
		pages[${sect}]+=( $page )
	else
		printf "\nNo description for ${adoc}!\n"
		fails=yes
	fi

	asciidoctor \
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

	if [[ $? -ne 0 ]]
	then
		printf "\nFailed to process ${adoc}!\n"
		fails=yes
	fi
	htmls[${html}]=${adoc}

done

printf "\nProcessing index: "

index=${dstman}/index.asc

cat <<EOF > ${index}
= NNG Reference Manual: ${VERSION}

The following pages are present:

EOF

for sect in $(echo ${!pages[@]} | sort )
do
	title=$(cat ${srcdir}/man${sect}.sect)
	desc=$(cat ${srcdir}/man${sect}.desc)
	printf "\n== Section ${sect}: ${title}\n";
	printf "\n${desc}\n";

	printf "\n[cols=\"3,5\"]\n"
	printf "|===\n"
	for page in $(echo ${pages[$sect][@]} | tr " " "\n" | sort)
	do
		printf "|<<${page}.${sect}#,${page}(${sect})>>\n"
		printf "|${descs[${page}_${sect}]}\n"
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

asciidoctor \
	-darticle \
	-anofooter=yes \
	-askip-front-matter \
	-atoc=left \
	-aicons=font \
	-aoutdir=${dstman} \
	-bhtml5 \
	-o - ${index} >> ${dstman}/index.html

htmls["index.html"]=${index}

cd $dstman

printf "\nRemoving old files: "
for f in *.html
do
	if [[ -z "${htmls[$f]}" ]]
	then
		git rm $f
	fi
done

printf "\nAdding new files: "
git add ${!htmls[@]}
chmod 0644 ${!htmls[@]}

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

git commit -m "man page updates for ${VERSION}"; git push origin gh-pages
