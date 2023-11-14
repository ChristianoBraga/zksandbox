#!/usr/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [ $# != 3 ]
then
    echo "Wrong number of arguments."
    echo "USE: in_proof.sh <proof key> <query hash> <secret data hash>"
   exit 1
fi

PK=$1  # Proof key 
QH=$2  # Query hash
SDH=$3 # Secret data hash

LOG=`lurk inspect --full $PK --proofs-dir .`

function check() {
    echo $1 | grep -w -q $2
    if [[ $? == 0 ]]
    then
        echo -e "${GREEN}✓${NC} Hash ${GREEN}$2${NC} found in proof $PK."
        return 0
    else 
        echo -e "${RED}✗${NC} Hash ${RED}$2${NC} not found in proof $PK."
        return 1
    fi
}

check "$LOG" $QH
FOUND_QH=$?
check "$LOG" $SDH
FOUND_SDH=$?

if [ $((FOUND_QH + FOUND_SDH)) == 0 ]
then
    echo -e "${GREEN}Proof check successful.${NC}"
else
    echo -e "${RED}Proof check unsuccessful.${NC}"
fi
