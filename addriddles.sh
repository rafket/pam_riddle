#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "This action must be run as root" 1>&2
    exit 1
elif [ $# -ne 2 ]
    then
        echo -e "Usage: addriddles.sh questions answers\n  Adds a list of riddles to the database\n";
else
    while read line
        do
	    echo ${line} >> /usr/share/riddles/questions
    done < $1

    while read line
        do
            echo -n ${line} | sha256sum | sed 's/  -//g' | xxd -r -p >> /usr/share/riddles/answers
    done < $2
fi
