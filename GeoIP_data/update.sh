#!/usr/bin/bash

# Source: http://dev.maxmind.com/geoip/legacy/geolite/

FILES="
http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
"

for url in $FILES; do
    IFS='/' read -a url_chunks <<< "$url"
    chunk_count=${#url_chunks[@]}
    last_position=$((chunk_count - 1))
    filename=${url_chunks[${last_position}]}
   
    rm -rf *.dat

    if [[ -f $filename ]]
    then 
            rm -rf $filename
    else
       wget -nv $url
    fi
done;
