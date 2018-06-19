#!/bin/bash

IFS='
'

for X in `objdump -rd $1 | grep -B1 "R_X86_64_*" | grep -v "R_X86_64\|--"  | sed -n 's/.*\(.. ..\) 00 00 00 00\s*\([^[:space:]]*\)\s.*/\1 \2/p' | sort | uniq -c | sort -nr`; do
	S=`echo $X | sed -n 's/.* \(.. ..\) .*/\1/p'`;
	# echo $S;
	Y=`objdump -rd $1 | grep -o $S | wc -l`
	echo $X on $Y entrys;
done


