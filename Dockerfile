FROM netsampler/goflow2:latest AS goflow2_src
FROM maxmindinc/geoipupdate:latest AS geoipupdate_src

FROM python:3.12-slim

RUN pip install --no-cache-dir maxminddb

COPY --from=goflow2_src /goflow2 /usr/local/bin/goflow2
COPY --from=geoipupdate_src /usr/bin/geoipupdate /usr/local/bin/geoipupdate

WORKDIR /app
COPY flow_analyzer.py ti_updater.py daily_summary.py web_server.py netmon.py flow-analyzer ti-updater daily-summary web-server index.html /app/
RUN chmod +x /app/netmon.py /app/flow-analyzer /app/ti-updater /app/daily-summary /app/web-server

ENV NETMON_DATA_DIR=/data/netmon \
    NETMON_FLOWS_FILE=/data/netmon/flows.jsonl

EXPOSE 2055/udp
EXPOSE 49210/tcp

ENTRYPOINT ["/app/netmon.py"]
