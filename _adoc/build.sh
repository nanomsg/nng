#!/bin/sh

# This shell script takes our content from _adoc and runs it through
# asciidoctor and applies front matter that Jekyll will see.  Its kind
# of annoying, since Jekyll on github-pages doesn't support asciidoctor
# properly.

aargs="-aicons=font -alinkcss"
cd $(dirname $0)
for f in $(find . -name '*.adoc'); do

	input=${f#./}
	indir=$(dirname $f)
	indir=${indir#./}
	output=../${input%.adoc}.html
        outdir=../${indir}

	when=$(git log -n1 --format='%ad' '--date=format-local:%s' $f)
	echo "Processing $input -> $output"

	if [ -n "$indir" ] && [ ! -d "$outdir" ]
	then
		mkdir -p $outdir
	fi

	echo generating $output
	env SOURCE_DATE_EPOCH=${when} asciidoctor ${aargs} -b html5 -o $output -a skip-front-matter $input
done
