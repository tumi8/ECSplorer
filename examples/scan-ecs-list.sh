#!/bin/bash

BASEDIR="/tmp"

DATEPATH="$(date '+%Y')/$(date '+%m')/$(date '+%Y-%m-%d-%H%M')"
OUTPUTDIR="${BASEDIR}/${DATEPATH}"

echo "Writing results to ${OUTPUTDIR}"

mkdir -p ${OUTPUTDIR}


pfile=$1

if [[ ! -e ${pfile} ]]; then
	echo "No prefix file provided"
	exit 1
fi

ifile=$2

if [[ ! -e ${ifile} ]]; then
	echo "No domain file provided"
	exit 1
fi

SCRIPTDIR=$(dirname "$(readlink -f "$0")")

if [[ ! -e ${SCRIPTDIR}/ecsplorer ]]; then
	echo "ECSplorer binary must be located at ${SCRIPTDIR}/ecsplorer"
	exit 1
fi

${SCRIPTDIR}/ecsplorer -query-list=${pfile} -if ${ifile} -ni=3 -query-rate=200 -out ${OUTPUTDIR}/list-results -domain-outstanding=100 &> ${OUTPUTDIR}/scan.log
