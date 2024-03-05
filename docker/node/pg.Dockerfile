FROM postgres:latest

RUN mkdir -p /docker-entrypoint-initdb.d

COPY ./pg-init.sql /docker-entrypoint-initdb.d/pg-init.sql
