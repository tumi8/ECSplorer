#!/bin/bash
set -e

BASEDIR="/tmp"

DATEPATH="$(date '+%Y')/$(date '+%m')/$(date '+%Y-%m-%d-%H%M')"
OUTPUTDIR="${BASEDIR}/${DATEPATH}"

echo "Writing results to ${OUTPUTDIR}"

LATESTPFS=$1

if [[ ! -e ${LATESTPFS} ]]; then
	echo "No prefix file provided"
	exit 1
fi

DOMAINSFILE=$2

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

	first_lastl=$(tail -n1 ${first_file} | cut -d. -f1)

#	echo "removing ${first_lastl} from ${second_file}"
	grep -e "^${first_lastl}." ${second_file} >> ${first_file}
	grep -v -e "^${first_lastl}." ${second_file} >> ${second_file}.tmp
	mv ${second_file}.tmp ${second_file}
}

mkdir -p ${OUTPUTDIR}

declare -a scan_pids=()
echo "scanning domain in $1"
for domain in $(cat $1); do
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
	NSIPS=($(echo "${nsall}" | grep -v alias | cut -d " " -f 4 | xargs -L1 dig +short ))
	echo "${NSIPS[@]}"
	numnsips=${#NSIPS[@]}

	OUTPUTBASE="${OUTPUTDIR}/${domain}"
	OUTPUT="${OUTPUTBASE}/ecsresults"
	mkdir -p ${OUTPUTBASE}

	PFXS_COUNT=$(wc -l ${LATESTPFS} | cut -d " " -f1)
	SPLIT_SIZE=$(( ${PFXS_COUNT} / ${numnsips} + 1 ))

	echo "splitting prefixes"
	split -d -l ${SPLIT_SIZE} ${LATESTPFS} ${OUTPUTBASE}/$(basename ${LATESTPFS}).split-

	for i in $(seq 0 $(( ${numnsips} - 2 )) ); do
		merge ${OUTPUTBASE}/$(basename ${LATESTPFS}).split-0${i} ${OUTPUTBASE}/$(basename ${LATESTPFS}).split-0$(( $i + 1 ))
	done

	BGPFILES=($(find ${OUTPUTBASE} -name "$(basename ${LATESTPFS}).split*" -type f))

	echo "starting scans"
	for i in $(seq 0 $(( ${numnsips} - 1 )) ); do
		pfile=(${BGPFILES[$i]})
		indexoutput=${OUTPUT}-${i}
		ifile=${OUTPUTBASE}/ns-${i}
		echo "${domaintorequest},${NSIPS[$i]}" > ${ifile}
		mkdir -p ${indexoutput}
		echo "prefix file: ${pfile}" >> ${indexoutput}/metadata
		echo "input file: ${ifile}" >> ${indexoutput}/metadata
		${SCRIPTDIR}/ecsplorer -pf=${pfile} -sf=${SCRIPTDIR}/specialPrefixes.csv -if ${ifile} -pl 24 -ni=3 -query-rate=50 -out ${indexoutput}/results -randomizeDepth 8 &> ${indexoutput}/scan.log &
		scan_pids[${#scan_pids[@]}]=$!
	done
done

for pid in "${scan_pids[@]}"; do
   wait "$pid"
done

echo "finished scanning"
