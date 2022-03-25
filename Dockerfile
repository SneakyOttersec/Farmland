#syntax=docker/dockerfile:1
FROM ubuntu:20.04
RUN apt update && apt install git python3.8 python3-pip -y
RUN pip3 install xlsxwriter
RUN mkdir /tool
RUN cd /tool
COPY ./Modules /tool/Modules 
COPY ./Resources /tool/Resources
COPY ./Logs /tool/Logs
COPY ./main.py /tool/main.py
COPY ./requirements.txt /tool/requirements.txt
RUN pip3 install -r /tool/requirements.txt
