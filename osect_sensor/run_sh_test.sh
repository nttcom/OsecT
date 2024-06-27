#!/bin/bash

compose_file=docker-compose.sh_test.yml
container_name=$(cat ${compose_file} | grep -E '^\s+container_name:\s*.+' | sed -r 's/^\s+container_name:\s*//g')
docker compose -f ${compose_file} down
docker compose -f ${compose_file} up
exit $(docker inspect --format='{{.State.ExitCode}}' ${container_name})
