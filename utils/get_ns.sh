#!/bin/bash

SCRIPTDIR=$(dirname "$(readlink -f "$0")")

set -e

datestr=$(date +%Y-%m-%d)
basepath=./${datestr}
mkdir -p ${basepath}

sourceout=${basepath}/source
mkdir -p ${sourceout}
sourcein=$1
if [[ -z ${sourcein} || ! -r ${sourcein} ]]; then
    echo "input file ('${sourcein}') not specified or not readable"
    exit 1
fi
ln -s ${sourcein} ${sourceout}/source.ln
cat ${sourcein} | parallel -j 2 --pipe --lb python3 ${SCRIPTDIR}/getNS.py - > ${sourceout}/scan.${datestr}.json 2> ${sourceout}/scan.${datestr}.error

python create-scan-input.py ${sourceout}/scan.${datestr}.json  ${sourceout}/scan.${datestr}.scan-input.csv

python create-scan-input.py -6 ${sourceout}/scan.${datestr}.json  ${sourceout}/scan.${datestr}.scan-input-6.csv

sort -S 20% --compress-program=lz4 --temporary-directory=/tmp -u ${sourceout}/scan.${datestr}.scan-input.csv ${sourceout}/scan.${datestr}.scan-input-6.csv | sort -R -S 20% --compress-program=lz4 --temporary-directory=/tmp > ${basepath}/scan-input.csv

cp /mnt/turbodiesel/ecs-scan/cnamescanning/prefixes.txt ${basepath}/prefixes.txt

echo "scan input is now ready to be scanned at ${basepath}/scan-input.csv"
echo "use the following exemplary command to start an ecsplorer scan (prefixes.txt must be changed to a file with a list of prefixes if a prefix list scan is selected):"
echo "
${SCRIPTDIR}/ecsplorer -query-list prefixes.txt -if ${basepath}/scan-input.csv -out ${basepath}/ecsresults -query-rate=100"
