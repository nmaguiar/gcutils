FROM openaf/oaf:t8 as main

USER root
COPY ojobs/collect4pid_live.yaml /openaf/ojobs/collect4pid_live.yaml
RUN sed -i 's/v[0-9]*\.[0-9]*/edge/g' /etc/apk/repositories\
 && apk update\
 && apk upgrade --available\
 && apk del openjdk21-jre openjdk21-jre-headless\
 && apk add --no-cache bash bash-completion vim tar gzip mc tmux python3 py3-pip strace openjdk21 prometheus grafana\
 && cd /openaf\
 && java -jar openaf.jar --install\
 && /openaf/openaf --update --force\
 && /openaf/opack install py-textual\
 && /openaf/opack install plugin-xls\
 && /openaf/opack install oafproc\
 && /openaf/opack install nattrmon\
 && /openaf/ojob ojob.io/get job=ojob.io/oaf/colorFormats.yaml > /openaf/ojobs/colorFormats.yaml\
 && /openaf/ojob ojob.io/get job=ojob.io/java/grafana/gc.yaml > /openaf/ojobs/grafana_gc.yaml\
 && /openaf/oaf --sb /openaf/ojobs/colorFormats.yaml\
 && /openaf/oaf --sb /openaf/ojobs/grafana_gc.yaml\
 && /openaf/oaf --sb /openaf/ojobs/collect4pid_live.yaml\
 && chown -R openaf:0 /openaf\
 && chown openaf:0 /openaf/.opack.db\
 && chmod -R u+rwx,g+rwx,o+rx,o-w /openaf/*\
 && chmod a+rwx /openaf\
 && rm /lib/apk/db/*\
 && sed -i "s/\/bin\/sh/\/bin\/bash/g" /etc/passwd
 
# Setup bash completion
# ---------------------
RUN /openaf/oaf --bashcompletion all > /openaf/.openaf_completion.sh\
 && chmod a+x /openaf/.openaf_*.sh\
 && chown openaf:openaf /openaf/.openaf_*.sh\
 && echo ". /openaf/.openaf_completion.sh" >> /etc/bash/start.sh

# Copy nattrmon config objects
# ----------------------------
COPY nattrmon/objects/nInput_CollectAllGC.js /openaf/nAttrMon/config/objects/nInput_CollectAllGC.js
COPY nattrmon/objects/nOutput_PrometheusFiles.js /openaf/nAttrMon/config/objects/nOutput_PrometheusFiles.js
RUN chmod u+rwx,g+rwx /openaf/nAttrMon/config/objects/*\
 && chown openaf:0 /openaf/nAttrMon/config/objects/*

# Setup gcutils folder
# ---------------------
RUN mkdir /gcutils\
 && chmod a+rwx /gcutils\
 && chown openaf:0 /gcutils

# Copy scripts
# ------------
COPY scripts /usr/bin
RUN chmod a+x /usr/bin/start_prom_graf.sh\
 && chmod a+x /usr/bin/openmetrics2prom.sh\
 && /openaf/oaf --sb /usr/bin/chooseJava.js\
 && chmod a+x /usr/bin/chooseJava.js

# Setup welcome message and vars
# ------------------------------
COPY welcome.txt /etc/gcutils
RUN gzip /etc/gcutils\
 && echo "zcat /etc/gcutils.gz" >> /etc/bash/start.sh\
 && echo "echo ''" >> /etc/bash/start.sh\
 && echo "alias oafptab='oafp in=lines linesvisual=true linesjoin=true out=ctable'" >> /etc/bash/start.sh\
 && echo "alias oaf-light-theme='colorFormats.yaml op=set theme=thin-light-bold'" >> /etc/bash/start.sh\
 && echo "alias oaf-dark-theme='colorFormats.yaml op=set theme=thin-intense-bold'" >> /etc/bash/start.sh\
 && echo "alias help='source /etc/bash/start.sh'" >> /etc/bash/start.sh\
 && echo "export PATH=$PATH:/openaf:/openaf/ojobs" >> /etc/bash/start.sh\
 && echo "echo ''" >> /etc/bash/start.sh
#&& cp /etc/bash/start.sh /etc/profile.d/start.sh

# Setup usage and examples
# ------------------------
COPY USAGE.md /USAGE.md
COPY EXAMPLES.md /EXAMPLES.md
COPY entrypoint.sh /.entrypoint.sh
RUN gzip /USAGE.md\
 && gzip /EXAMPLES.md\
 && echo "#!/bin/sh" > /usr/bin/usage-help\
 && echo "zcat /USAGE.md.gz | oafp in=md mdtemplate=true | less -r" >> /usr/bin/usage-help\
 && echo "#!/bin/sh" > /usr/bin/examples-help\
 && echo "zcat /EXAMPLES.md.gz | oafp in=md mdtemplate=true | less -r" > /usr/bin/examples-help\
 && chmod a+x /usr/bin/usage-help\
 && chmod a+x /usr/bin/examples-help\
 && chmod a+x /.entrypoint.sh

# -------------------
FROM scratch as final

COPY --from=main / /

ENV OAF_HOME=/openaf
ENV PATH=$PATH:$OAF_HOME:$OAF_HOME/ojobs
USER openaf

WORKDIR /gcutils
#CMD ["/usr/bin/usage-help"]
ENTRYPOINT ["/.entrypoint.sh"]