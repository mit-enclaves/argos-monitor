#!/bin/bash

cat "$1" | while read first_line; read second_line; read third_line
do
    echo -e "$first_line\t$second_line\t$third_line"
done

# for f in `seq 3`; do
#     addr=$(read line <&6)
#     func=$(read line <&6)
#     file=$(read line <&6)
#     echo "$addr\t$func\t$file"
# done

# exec 6<&-
# 
# cat "$1" | while read line 
# do
#    # do something with $line here
# done
