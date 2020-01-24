#!/bin/bash

# I hereby place this script is in the public domain. - Garrett D'Amore <garrett@damore.org>  Jan 23, 2020.

# Usage:
#
# pubrefman.sh <version>
#
# This will checkout the named version (which may be "master" for tip), run asciidoctor over the files,
# prepend standard boilerplate to them, and ...

ver=$1
if [ "${ver}" == "" ]; then
        ver=tip
        tag=master
else
        tag=${ver}
fi
scratch=$(mktemp -d --tmpdir pubrefmanXXXXXX)
trap 0 "rm -rf ${scratch}"
repo=$(dirname $0)/..
giturl=https://github.com/nanomsg/nng

# checkout the repo
git clone ${giturl} ${scratch}/nng
(cd ${scratch}/nng; git checkout $tag)

mkdir ${scratch}/html
mkdir ${scratch}/adoc
cp ${scratch}/nng/docs/man/*.adoc ${scratch}/adoc

getdesc() {
        typeset input=$1
        typeset -i doname=0
        typeset line
        while read line
        do
                case "$line" in
                "== NAME")
                        doname=1
                        ;;
                "=="*)
                        doname=0
                        ;;
                "//*"|"")
                        ;;
                *" - "*)
                        if (( doname ))
                        then
                                echo ${line#*- }
                                return
                        fi
                        ;;
                esac
        done < ${input}
}

time asciidoctor \
	-dmanpage \
	-amansource="NNG" \
	-amanmanual="NNG Reference Manual" \
	-anofooter=yes \
	-atoc=left \
	-aicons=font \
	-asource-highlighter=pygments \
	-alinkcss \
	-bhtml5 \
	-D ${scratch}/html \
	${scratch}/adoc/*.adoc

typeset -A descs
typeset -A pages

for f in ${scratch}/adoc/*.adoc; do
        src=${f##*/}
        sect=${src%.adoc}
        sect=${sect##*.}
        pages[${sect}]="${pages[${sect}]} ${src}"
        descs[${src}]=$(getdesc $f)
done

index=${scratch}/adoc/index.adoc
for sect in $(echo ${!pages[@]} | sort ); do
        title=$(cat ${scratch}/nng/docs/man/man${sect}.sect)
        desc=$(cat ${scratch}/nng/docs/man/man${sect}.desc)
        printf "\n== Section ${sect}: ${title}\n" >> ${index}
        printf "\n${desc}\n" >> ${index}

        printf "\n[cols=\"3,5\"]\n" >> ${index}
        printf "|===\n" >> ${index}

        for page in $(echo ${pages[$sect]} | tr " " "\n" | sort ); do
                printf "|xref:${page}[${page%.adoc}(${sect})]\n" >> ${index}
                printf "|${descs[${page}]}\n\n" >> ${index}
        done
        printf "|===\n" >> ${index}
done

time asciidoctor \
	-darticle \
	-anofooter=yes \
	-atoc=left \
	-alinkcss \
	-bhtml5 \
	-D ${scratch}/html \
	${scratch}/adoc/index.adoc


#
# Generation is complete, now copy...
#
config=${repo}/_config.yml
if [ ! -f ${config} ]; then
        echo "Missing config file ${config}"
        exit 1
fi

if ! grep -q "man/${ver}" ${config}
then
        printf "  - scope:\n" >> ${config}
        printf "      path: \"man/${ver}\"\n" >> ${config}
        printf "    values:\n" >> ${config}
        printf "      layout: \"refman\"\n" >> ${config}
        printf "      version: \"${ver}\"\n" >> ${config}
        git add ${config}
fi

dest=${repo}/man/${ver}
mkdir -p ${dest}
add=""
for f in ${scratch}/html/*; do
        base=${f##*/}
        cp $f ${dest}/${base}
        add="${add} ${dest}/${base}"
done
git add ${add}
for f in ${dest}/*; do
        base=${f##*/}
        if [ ! -f ${scratch}/html/${base} ]; then
                echo "removing ${f} (not in ${scratch}/html/${base})"
                git rm ${f}
        fi
done

git commit -m "Publishing updates for ${ver}"

printf "A final push should be done once changes are verified.\n"