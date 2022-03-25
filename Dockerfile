#syntax=docker/dockerfile:1
FROM ubuntu:20.04
RUN apt update && apt git install python3.8 python3-pip -y
RUN pip3 install xlsxwriter
