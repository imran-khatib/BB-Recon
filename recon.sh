#!/bin/bash

domain=$1
wordlist="/root/tools/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
resolvers="/root/tools/resolvers.txt"
resolve_domain="/root/tools/massdns/bin/massdns -r /root/tools/resolvers.txt -t A -o S -w"
output_dir="$domain/recon"

# Ensure domain is provided
if [ -z "$domain" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

setup_directories() {
    mkdir -p $output_dir/{sources,Recon/{Knockpy,findomain,github_subdomains,nuclei,wayback,ssrf,Params,eyewitness,gf,wordlist,masscan}}
}

subdomain_enum() {
    subfinder -d $domain -all -o $output_dir/sources/subfinder.txt
    assetfinder -subs-only $domain | anew -q $output_dir/sources/assetfinder.txt
    amass enum -passive -d $domain -o $output_dir/sources/passive.txt &
    findomain --quiet -t $domain -u $output_dir/Recon/findomain/findomain_psub.txt 
    shuffledns -d $domain -w $wordlist -r $resolvers -o $output_dir/sources/shuffledns.txt -silent
    cat $output_dir/sources/*.txt > $output_dir/sources/all.txt
}

resolving_domains() {
    naabu -list $output_dir/sources/all.txt -o $output_dir/sources/naabu_findings.txt
    shuffledns -d $domain -list $output_dir/sources/all.txt -o $output_dir/domains.txt -r $resolvers -silent
}

http_prob() {
    cat $output_dir/domains.txt | httpx -threads 200 -o $output_dir/Recon/httpx-live.txt
}

scanner() {
    echo -e "\e[1;33m *******Scanning domain with Nuclei********\e[0m"
    templates=(fuzzing cves files exposed-panels misconfiguration technologies takeovers vulnerabilities bugs-misconfigs exposures workflow helpers default-logins)
    for template in "${templates[@]}"; do
        cat $output_dir/sources/all.txt | nuclei -t /root/nuclei-templates/$template/ -c 60 -o $output_dir/Recon/nuclei/$template.txt
    done
}

detection_op() {
    echo "Looking for HTTP request smuggling"
    python3 ~/smuggler/smuggler.py -u $output_dir/sources/all.txt | tee -a $output_dir/Recon/smuggler_op.txt

    echo "Now looking for CORS misconfiguration"
    python3 ~/Corsy/corsy.py -i $output_dir/sources/all.txt -t 40 | tee -a $output_dir/Recon/corsy_op.txt

    echo "Starting CMS detection"
    whatweb -i $output_dir/sources/all.txt | tee -a $output_dir/Recon/whatweb_op.txt
}

jsep() {
    mkdir -p scripts scriptsresponse endpoints responsebody headers

    response() {
        echo "Gathering Response"
        for x in $(cat $output_dir/sources/all.txt); do
            NAME=$(echo $x | awk -F/ '{print $3}')
            curl -X GET -H "X-Forwarded-For: evil.com" $x -I > "headers/$NAME"
            curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x > "responsebody/$NAME"
        done
    }

    jsfinder() {
        echo "Gathering JS Files"
        for x in $(ls "responsebody"); do
            printf "\n\n${RED}$x${NC}\n\n"
            END_POINTS=$(cat "responsebody/$x" | grep -Eoi "src=\"[^>]+></script>" | cut -d '"' -f 2)
            for end_point in $END_POINTS; do
                len=$(echo $end_point | grep "http" | wc -c)
                mkdir "scriptsresponse/$x/" > /dev/null 2>&1
                URL=$end_point
                if [ $len == 0 ]; then
                    URL="https://$x$end_point"
                fi
                file=$(basename $end_point)
                curl -X GET $URL -L > "scriptsresponse/$x/$file"
                echo $URL >> "scripts/$x"
            done
        done
    }

    endpoints() {
        echo "Gathering Endpoints"
        for domain in $(ls scriptsresponse); do
            mkdir endpoints/$domain
            for file in $(ls scriptsresponse/$domain); do
                ruby ~/tools/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >> endpoints/$domain/$file 
            done
        done
    }

    response
    jsfinder
    endpoints
}

wayback_data() {
    mkdir $output_dir/wayback_data
    cd $output_dir/wayback_data

    for i in $(cat ../all.txt); do
        echo $i | waybackurls
    done | tee -a wb.txt

    cat wb.txt | sort -u | unfurl --unique keys | tee -a paramlist.txt
    cat wb.txt | grep -P "\w+\.js(\?|$)" | sort -u | tee -a jsurls.txt
    cat wb.txt | grep -P "\w+\.php(\?|$)" | sort -u | tee -a phpurls.txt
    cat wb.txt | grep -P "\w+\.aspx(\?|$)" | sort -u | tee -a aspxurls.txt
    cat wb.txt | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a jspurls.txt
    cat wb.txt | grep -P "\w+\.txt(\?|$)" | sort -u | tee -a robots.txt

    cd ..
}

gf_patterns() {
    gf xss $output_dir/wayback/valid.txt | tee -a $output_dir/gf/xss.txt
    gf sqli $output_dir/wayback/valid.txt | tee -a $output_dir/gf/sqli.txt
    gf cors $output_dir/wayback/valid.txt | tee -a $output_dir/gf/cors.txt
    gf idor $output_dir/wayback/valid.txt | tee -a $output_dir/gf/idor.txt
    gf firebase $output_dir/wayback/valid.txt | tee -a $output_dir/gf/firebase.txt
    gf takeover $output_dir/wayback/valid.txt | tee -a $output_dir/gf/takeover.txt
    gf rce $output_dir/wayback/valid.txt | tee -a $output_dir/gf/rce.txt
    gf lfi $output_dir/wayback/valid.txt | tee -a $output_dir/gf/lfi.txt
    gf s3-buckets $output_dir/wayback/valid.txt | tee -a $output_dir/gf/s3-buckets.txt
    gf ssti $output_dir/wayback/valid.txt | tee -a $output_dir/gf/ssti.txt
}

eyewitness() {
    terminator -e "eyewitness --web -f $output_dir/domains.txt -d $output_dir/eyewitness/screenshots" -p hold


}

dirbust() {
    gobuster dir -u http://$domain -w /root/wordlist -t 100 -o gobuster.txt
    feroxbuster -u http://$domain -w /root/wordlist -t 200 -o feroxbuster.txt
}

port_scan() {
    masscan -iL $domain/domains.txt -p1-65535 -oX $output_dir/masscan/$domain.xml --rate=1000
}

ffuf_scan() {
    cat $output_dir/sources/all.txt | httpx -threads 100 -silent -status-code -title -tech-detect -follow-redirects -mc 200 -o $output_dir/Recon/httpx/httpx.txt
    mkdir -p $output_dir/Recon/httpx/
    cat $output_dir/Recon/httpx/httpx.txt | cut -d ' ' -f1 | sort -u | tee -a $output_dir/Recon/httpx/httpx-urls.txt

    xargs -P 25 -I % bash -c 'ffuf -u %FUZZ -w /root/wordlist -c -v -s -o $output_dir/Recon/ffuf/%-ffuf.txt' < $output_dir/Recon/httpx/httpx-urls.txt
}

# Execution flow
# setup_directories
# subdomain_enum
# resolving_domains
# http_prob
# scanner
# detection_op
# jsep
# wayback_data
# gf_patterns
# eyewitness
# dirbust
# port_scan
# ffuf_scan


