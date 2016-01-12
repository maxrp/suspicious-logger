#!/usr/bin/env bash

# Source: http://dev.maxmind.com/geoip/legacy/geolite/

FILES="
http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
"

DATADIR=$(dirname `readlink -f ${BASH_SOURCE[0]}`)

cd ${DATADIR}

for url in $FILES; do
    IFS='/' read -a url_chunks <<< "$url"
    chunk_count=${#url_chunks[@]}
    last_position=$((chunk_count - 1))
    filename=${url_chunks[${last_position}]}
  
    if [[ -f $filename ]]; then rm -rf "${filename}"; fi

    wget -nv $url
    if [[ -f ${filename%.gz} ]]; then rm -v "${filename%.gz}"; fi
    gunzip -v "${filename}"
done;
