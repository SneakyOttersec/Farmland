# Most of the Dockerfile come frome Intrigue.io
FROM debian:bullseye-slim

ENV CHROME_BIN=/usr/bin/chromium \
    CHROME_PATH=/usr/lib/chromium/ \
    GEM_HOME="/home/ident/.gem"

RUN apt update && apt install git python3.9 python3-pip -y
RUN pip3 install xlsxwriter

RUN adduser --disabled-password --gecos "" ident \
    && apt-get update \
    && apt-get install -yq apt-utils build-essential curl gcc \
       libbison-dev libcurl4-openssl-dev libgdbm-compat-dev libgdbm-dev \
       libgmp-dev libharfbuzz-dev libssl-dev libxml2-dev libxslt1-dev openssl \
       readline-common git nano wget \
    && mkdir -p /src/ruby  \
    && cd /src/ruby \
    && curl -O https://cache.ruby-lang.org/pub/ruby/2.7/ruby-2.7.2.tar.gz \
    && tar -xvzf ruby-2.7.2.tar.gz \
    && cd ruby-2.7.2 \
    && ./configure --disable-install-rdoc \
    && make && make install \
    && rm -rf /var/cache/apt/* \
    && cd / \
    && rm -rf /src/ruby/  \
       /usr/local/share/{doc,man}
# Farmland - nrich
RUN wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb
RUN dpkg -i nrich_latest_amd64.deb
# Farmland
COPY ./entrypoint.sh /tool/entrypoint.sh
COPY ./Modules /tool/Modules
COPY ./Resources /tool/Resources
COPY ./main.py /tool/main.py
COPY ./requirements.txt /tool/requirements.txt
COPY ./Logs /tool/logs
# Install dnsrecon prereq
RUN pip install -r /tool/Resources/Scripts/dnsrecon/requirements.txt

RUN mkdir /tool/Output/ && \
     mkdir /tool/Output/Formatted
     
RUN mkdir /tool/Output/Raw && \
    mkdir /tool/Logs
RUN pip3 install -r /tool/requirements.txt

ADD ./Resources/Binary/intrigue-ident/ /tool/Resources/Binary/ident
RUN chown root /tool/Resources/Binary/massdns && \
    chown root /tool/Resources/Binary/masscan
RUN chmod 4777 /tool/Resources/Binary/massdns && \
    chmod 4777 /tool/Resources/Binary/masscan
WORKDIR /tool/Resources/Binary/ident
RUN cd /tool/Resources/Binary/intrigue-ident && \
    gem install bundler:2.0.2 \
    && bundle install
WORKDIR /tool
#USER ident
#ENTRYPOINT ["/tool/entrypoint.sh"]
