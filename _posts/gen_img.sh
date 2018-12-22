#! /bin/bash


if [ $# != 1 ];then
	echo "$0 xxx.img"
	exit
fi

ls $1 &>> /dev/null

if [ $? != 0 ];then
	echo "$1 not exists!"
	exit
fi

filepath="../assets/img/md/"

filename="`date +%F`-$RANDOM$RANDOM.img"

ls $filepath/$filename &>> /dev/null

while [ $? -eq 0 ];do
	filename="`date +%F`-$RANDOM$RANDOM.img"
done

file="${filepath}${filename}"

echo "filepath: `echo $file | cut -c 3-`"

mv $1 $file

if [ $? -eq 0 ];then
	echo "ok"
fi
