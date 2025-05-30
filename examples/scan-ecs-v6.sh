#!/bin/bash

set -eu

BASEDIR="/tmp"

DATEPATH="$(date '+%Y')/$(date '+%m')/$(date '+%Y-%m-%d-%H%M')"
OUTPUTDIR="${BASEDIR}/${DATEPATH}"

echo "Writing results to ${OUTPUTDIR}"

LATESTPFS=$2

if [[ ! -e ${LATESTPFS} ]]; then
	echo "No prefix file provided"
	exit 1
fi

DOMAINSFILE=$1

if [[ ! -e ${DOMAINSFILE} ]]; then
	echo "No domain file provided"
	exit 1
fi

SCRIPTDIR=$(dirname "$(readlink -f "$0")")

if [[ ! -e ${SCRIPTDIR}/ecsplorer ]]; then
	echo "ECSplorer binary must be located at ${SCRIPTDIR}/ecsplorer"
	exit 1
fi

function merge {
	first_file=$1
	second_file=$2

	first_lastl=$(tail -n1 ${first_file} | cut -d: -f1)

	grep -e "^${first_lastl}:" ${second_file} >> ${first_file} || true
	grep -v -e "^${first_lastl}:" ${second_file} >> ${second_file}.tmp || true
	mv ${second_file}.tmp ${second_file}
}

mkdir -p ${OUTPUTDIR}

declare -a scan_pids=()
echo "scanning domain in ${DOMAINSFILE}"
for domain in $(cat ${DOMAINSFILE}); do
	echo "scanning ${domain}"
	nsall=$(host -t ns ${domain})
	cname=$(echo "${nsall}" | grep alias | tail -n 1 | cut -d " " -f 6)
	domaintorequest=${domain}
	while [[ -n "${cname}" ]]; do
		domaintorequest=${cname}
		nsall=$(host -t ns ${cname})
		cname=$(echo "${nsall}" | grep alias | tail -n 1 | cut -d " " -f 6)
	done

	domainred=${domaintorequest}
	while echo "${nsall}" | grep -q -F "no NS record" || echo "${nsall}" | grep -q -F "NXDOMAIN" ; do
		domainred=$(echo "${domainred}" | cut -d. -f 2-)
		nsall=$(host -t ns ${domainred} || true)
	done
	NSIPS=($(echo "${nsall}" | grep -v alias | cut -d " " -f 4 | xargs -L1 dig +short aaaa))
	echo "ns IPs for ${domain}: ${NSIPS[@]}"
	numnsips=${#NSIPS[@]}

	OUTPUTBASE="${OUTPUTDIR}/${domain}"
	OUTPUT="${OUTPUTBASE}/ecsresults"
	mkdir -p ${OUTPUTBASE}

	INFILE=${OUTPUTBASE}/prefixes
	# sort -u -S 10% --compress-program lz4 ${LATESTIRR} ${LATESTPFS} > ${INFILE}

	cp ${LATESTPFS} ${INFILE}
	ln -s ${LATESTPFS} ${OUTPUTBASE}/bgp-origin
	# ln -s ${LATESTIRR} ${OUTPUTBASE}/irr-origin

	PFXS_COUNT=$(wc -l ${INFILE} | cut -d " " -f1)
	SPLIT_SIZE=$(( ${PFXS_COUNT} / ${numnsips} + 1 ))

	echo "splitting prefixes"
	split -d -l ${SPLIT_SIZE} ${INFILE} ${OUTPUTBASE}/$(basename ${INFILE}).split-

	for i in $(seq 0 $(( ${numnsips} - 2 )) ); do
		echo $i
		merge ${OUTPUTBASE}/$(basename ${INFILE}).split-0${i} ${OUTPUTBASE}/$(basename ${INFILE}).split-0$(( $i + 1 ))
	done

	BGPFILES=($(find ${OUTPUTBASE} -name "$(basename ${INFILE}).split*" -type f))
	#echo ${BGPFILES[@]}
	#echo ${INPUTFILES[@]}

	echo "starting scans"
	for i in $(seq 0 $(( ${numnsips} - 1 )) ); do
		pfile=(${BGPFILES[$i]})
		indexoutput=${OUTPUT}-${i}
		ifile=${OUTPUTBASE}/ns-${i}
		echo "${domaintorequest},${NSIPS[$i]}" > ${ifile}
		mkdir -p ${indexoutput}
		echo "prefix file: ${pfile}" >> ${indexoutput}/metadata
		echo "input file: ${ifile}" >> ${indexoutput}/metadata
		${SCRIPTDIR}/ecsplorer -pf=${pfile}  -sf=$(dirname ${SCRIPTDIR})/utils/specialPrefixes.csv  -pl 48 -if ${ifile} -ni=3 -query-rate=50 -6 -randomize-depth 32 -config-file ${SCRIPTDIR}/sample-config.yml -out ${indexoutput}/results -scanAllBGP &> ${indexoutput}/scan.log &
		scan_pids[${#scan_pids[@]}]=$!
	done
	sleep 5
done

for pid in "${scan_pids[@]}"; do
   wait "$pid"
done

echo "finished scanning"

