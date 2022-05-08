#!/bin/bash

output="$(python3 ./../src/main.py '--action' "$1" '--password' "$2" '--adress' "$3" '--new_password' "$4")"
echo $output

#store password to clipboard
password=$(echo $output | sed -r '/Password for adress.*/!d' | sed -r 's/Password for adress: .* (.*)/\1/g')

if [ -n "$password" ]
then
	copyq copy "$password" 2>&1 | grep -q '.*'
fi
