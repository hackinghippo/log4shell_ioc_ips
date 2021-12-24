#!/bin/bash
DIR=/home/pi/scripts/j4shell_ioc_ips
SIZEBEGIN=$(du -b $DIR/ips.txt | cut -f1)
# clone repos into dir
repos=("https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217" "https://github.com/Akikazuu/Apache-Log4j-RCE-Attempt" "https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs" "https://gist.github.com/ycamper/26e021a2b5974049d113738d51e7641d" "https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228/blob/main/Threatview.io-log4j2-IOC-list" "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv" "https://github.com/CronUp/Malware-IOCs/blob/main/2021-12-11_Log4Shell_Botnets" "https://gist.github.com/blotus/f87ed46718bfdc634c9081110d243166" "https://github.com/threatmonit/Log4j-IOCs" "https://github.com/Humoud/log4j_payloads" "https://gist.github.com/yt0ng/8a87f4328c8c6cde327406ef11e68726" "https://github.com/LogRhythm-Labs/log4Shell" "https://github.com/bengisugun/Log4j-IOC" "https://github.com/guardicode/CVE-2021-44228_IoCs" "https://github.com/shnoogie/log4j_ioc" "https://github.com/vul-log/log4j_iocs" "https://github.com/threatmonit/Log4j-IOCs" "https://github.com/aojald/LOG4J_IOC" "https://github.com/josephinetanadi/log4j-ioc-merge" "https://github.com/russelr46/IOC_log4j_apache" "https://github.com/prodigyak/Log4j-Wireshark-IOC-filter" "https://github.com/valtix-security/Log4j-Indicators-of-Compromise" "https://github.com/curated-intel/Log4Shell-IOCs" "https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs")
 
# add new downloads at the end!!
downloads=("https://threatfox.abuse.ch/export/csv/full/" "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv" "https://urlhaus.abuse.ch/downloads/csv/" "https://raw.githubusercontent.com/CronUp/Malware-IOCs/main/2021-12-11_Log4Shell_Botnets" "https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/log4j.txt" "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/log4j_ip.intel" "https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/log4j.txt" "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv" "https://raw.githubusercontent.com/eromang/researches/main/CVE-2021-44228/README.md")

if [ -d "./repos" ]; then
        find ./repos -type d -mindepth 1 -maxdepth 1 -exec git --git-dir={}/.git --work-tree=$PWD/{} pull  \;
else
        mkdir $DIR/repos
	mkdir $DIR/dl
        for str in ${repos[@]}; do
                git -C ./repos clone $str
        done
fi
echo "Downloading all files...."
i=0
for str in ${downloads[@]}; do
	i=$((i+1))
	curl $str --output $DIR/dl/$i
done

#extract file from tweetfeed
echo "extract files from tweetfeed...."
cat $DIR/dl/2 | grep  -i "log4j\|log4shell" | grep -i "ip" | awk -F ',' '{print $4}' > tweetfeedfiltered
rm $DIR/dl/2

# extract csv from urlhaus
echo "extract files from urlhaus...."
unzip -o $DIR/dl/3 -d $DIR/dl/
cat $DIR/dl/csv.txt | grep -i "log4j" | awk -F ',' '{print $3}' > urlhaus #grep for tags 
rm $DIR/dl/3
rm $DIR/dl/csv.txt

#extract files from threatfox
echo "extract files from threatfox...." 
unzip -o $DIR/dl/1 -d $DIR/dl/
cat $DIR/dl/full.csv | grep -i "log4j\|CVE-2021-44228" | awk -F ',' '{print $3}' > threatfox #grep for tags

rm $DIR/dl/1
rm $DIR/dl/full.csv


echo "backup from old ips.txt...."

cp $DIR/ips.txt ../ipsbak.txt

echo "grep all IPs...."
#grep all ips in repo dir
grep -hiRaE --exclude="README.md" --exclude="ips.txt" --exclude="script.sh" --exclude="stats.txt" -o  "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | grep -Pv "^(10(\.(1?\d\d?|2([0-4]\d?|5[0-5])))(?2)|172\.(1[6-9]|2\d|3[0-2])(?2)|192\.168(?2))(?2)$" | sort -u > $DIR/ips.txt




SIZEND=$(du -b $DIR/ips.txt | cut -f1)
# check if new ips..
if [[ $SIZEND != $SIZBEGIN  ]]; then
	echo "update list!!"
	TIMEDATE=$(date +"%D %T")
	LINECOUNT=$(wc -l ips.txt)
	OUTPUT="${TIMEDATE} : ${LINECOUNT}"
	echo "${OUTPUT} " >> $DIR/stats.txt 

	git add $DIR/stats.txt
	git add $DIR/ips.txt
	git add $DIR/script.sh
	git commit -m "hourly update"
	git push
fi

