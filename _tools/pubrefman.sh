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
trap "rm -rf ${scratch}" 0
repo=$(dirname $0)/..
giturl=https://github.com/nanomsg/nng

# checkout the repo
git clone -q ${giturl} ${scratch}/nng
(cd ${scratch}/nng; git checkout -q $tag)

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

asciidoctor \
        -q \
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

asciidoctor \
        -q \
	-darticle \
	-anofooter=yes \
	-atoc=left \
	-alinkcss \
	-bhtml5 \
	-D ${scratch}/html \
	${scratch}/adoc/index.adoc



dest=${repo}/man/${ver}
mkdir -p ${dest}
add=""
for f in ${scratch}/html/*; do

        # insert the header - HTML only
        case $f in
        *.html)
                printf "--" "---\nversion: ${ver}\nlayout: refman\n---\n" > ${f}.new
                cat ${f} >> ${f}.new
                mv ${f}.new ${f}
                ;;
        *.css)
                ;;
        esac

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

git commit -q -m "Publishing updates for ${ver}"

printf "A final push should be done once changes are verified.\n"