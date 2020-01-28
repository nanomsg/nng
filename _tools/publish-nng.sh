#!/bin/bash

# I hereby place this script is in the public domain. - Garrett D'Amore <garrett@damore.org>  Jan 23, 2020.

# Usage:
#
# publish-nng.sh <version>
#
# This publishes content from the _adoc directory into the main tree.  Individual files can be specified.
# It runs asciidoctor over the files, and massages them.

if [[ $# -gt 0 ]]
then
	files=$*
	echo "using user specified args ${files[@]}"
else
	files=$( find ../_adoc/ -type f -name '*.adoc' )
	echo "finding files ${files[@]}"
fi

scratch=$(mktemp -d --tmpdir pubnngXXXXXX)
trap "rm -rf ${scratch}" 0
dest=$(dirname $0)/..

for f in ${files[@]}
do
        base=${f##*/_adoc}
        dir=${base%/*}
        base=${base##/}

        asciidoctor \
                -q \
	        -darticle \
	        -anofooter=yes \
                -askip-front-matter \
	        -aicons=font \
	        -asource-highlighter=pygments \
	        -alinkcss \
	        -bhtml5 \
	        -D ${scratch}/${dir} \
                ${f}
done

process_html() {
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
                        ;;
                *)
                        if [[ -z "$skip" ]]; then
                                printf "%s\n" "$line"
                        fi
                        ;;
                esac
        done
}

add=""
for f in $(find ${scratch} -name '*.html' ); do

        base=${f##${scratch}}
        base=${base##/}

        # insert the header - HTML only
        process_html nng < ${f} > ${f}.new
        mv ${f}.new ${f}
        cp ${f} ${dest}/${base}
        add="${add} ${dest}/${base}"
done
git add ${add}
git commit -q -m "Publishing site updates"

printf "A final push should be done once changes are verified.\n"
