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
toc=${scratch}/html/_toc.html
printf "<nav id=\"toc\" class=\"toc2\">\n" > ${toc}
printf "<ul class=\"sectlevel1\n\">\n" >> ${toc}
printf "# NNG Reference Manual\n" >> ${index}
for sect in $(echo ${!pages[@]} | tr " " "\n" | sort ); do
        title=$(cat ${scratch}/nng/docs/man/man${sect}.sect)
        desc=$(cat ${scratch}/nng/docs/man/man${sect}.desc)
        printf "\n== Section ${sect}: ${title}\n" >> ${index}
        printf "\n${desc}\n" >> ${index}

        printf "\n[cols=\"3,5\"]\n" >> ${index}
        printf "|===\n" >> ${index}

        printf "<li>${title}</li>\n" >> ${toc}
        printf "<ul class=\"sectlevel2\">\n" >> ${toc}
        for page in $(echo ${pages[$sect]} | tr " " "\n" | sort ); do
                name=${page%.adoc}
                name=${name%.*}
                printf "|xref:${page}[${name}(${sect})]\n" >> ${index}
                printf "|${descs[${page}]}\n\n" >> ${index}
                printf "<li><a href=\"${page%.adoc}.html\">${name}</a></li>\n" >> ${toc}

        done
        printf "|===\n" >> ${index}
        printf "</ul>\n" >> ${toc}
done
printf "</ul>\n" >> ${toc}
printf "</nav>\n" >> ${toc}

asciidoctor \
        -q \
	-darticle \
	-anofooter=yes \
	-alinkcss \
	-bhtml5 \
	-D ${scratch}/html \
	${scratch}/adoc/index.adoc


process_manpage() {
        typeset skip=yes
        typeset layout=$1
        typeset ver=$2
        typeset title=""
        while read line; do
                # Look for the body tag, so that we strip off all the pointless
                # front matter, because we're going to replace that.   We
                # don't actually emit the body tags.  We also strip out any
                # link tags.
                case "$line" in
                "<title>"*)
                        title=${line#*'>'}
                        title=${title%'<'*}
                        ;;
                "<body"*)
                        printf -- "---\n"
                        printf "version: ${ver}\n"
                        printf "layout: ${layout}\n"
                        printf "title: ${title}\n"
                        printf -- "---\n"
                        printf "<main>\n"
                        skip=
                        ;;
                "</body"*)
                        printf "</main>\n"
                        skip=yes
                        ;;
                "<link"*)
                        # discard it
                        ;;
                *)
                        if [[ -z "$skip" ]]; then
                                printf "%s\n" "$line"
                        fi
                        ;;
                esac
        done
}

dest=${repo}/man/${ver}
mkdir -p ${dest}
add=""
for f in ${scratch}/html/*; do

        # insert the header - HTML only
        case $f in
        */_toc.html)
                # SKIP the TOC
                ;;
        *.html)
                process_manpage manpage ${ver} < ${f} > ${f}.new
                mv ${f}.new ${f}
                ;;
        *.css)
                continue
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