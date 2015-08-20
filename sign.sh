#! /bin/sh
#
# sigh.sh
# Copyright (C) 2015 dascheng <dascheng@DASCHENG-M-419E>
#
# Distributed under terms of the MIT license.
#


declare -a FILES
declare -a TOKENS1
declare -a TOKENS2

function file_exist {
if [[ ! -f $1  ]] ; then
    echo "!!! $1 not exit in current directory !!!"
    exit
fi

}

function do_sign {
local count=1
for i in $(ls *$1);
do
    echo "signing "$i
    file_exist $i
    out="${i%$1}$2"
    echo "mlosign -c snoopyplus release ${TOKENS1[0]} ${TOKENS1[$count]} ${TOKENS2[0]} ${TOKENS2[$count]} $i $out"
    ./mlosign -c snoopyplus release ${TOKENS1[0]} ${TOKENS1[$count]} ${TOKENS2[0]} ${TOKENS2[$count]} $i $out >> /dev/null 2>&1
    ((count++))
done

}

function get_files {
local count=0
for i in $(ls *bin);
do
    file_exist $i
    #eval concatenting arguments
    eval "$1"[$count]=$i
    ((count++))
done

}

function get_tokens {
local count=0
for word in $(<$1)
do
    #eval concatenting arguments
    eval "$2"[$count]=$word
    ((count++))
done

}

function get_size {
for file in $(cat *.preloads| grep -oh "\([0-9a-zA-Z]\+\.\)\{2,3\}sbn");
do
    file_exist $file
    val=`ls -all $file | awk '{print size=$5}'`
    sed  "s/$file @SIZE.*/$file size=$val/" *.preloads >> /dev/null 2>&1
done

}

#get_files "FILES"
echo "read tokens from signer1&signer2"
get_tokens "signer1" "TOKENS1"
get_tokens "signer2" "TOKENS2"
echo "start to sign the bin files"
do_sign "bin" "sbn"
get_size
echo "start to sign the preloads file"
#do_sign "preloads" "loads"

#elements=${#TOKENS1[@]}
#echo $elements
#for ((i=0;i<$elements;i++)); do
#    echo ${TOKENS1[${i}]}
#done

#printf "%s\n" "${TOKENS1[@]}"
#printf "%s\n" "${FILES[@]}"
function upload_file {
files=($(ls *bin))
for file in ${files[@]};
do
    echo "upload "$file" to 72.163.254.62"
    ftp -inv <<!
    open 72.163.254.62
    user dascheng 123456
    binary
    cd tftpboot
    echo "uploading "
    put $file
    bye
!
done
}
upload_file


