FROM centos:latest

RUN vim hello.txt

RUN sudo pwd

ADD README.md /app/

EXPOSE 80000
