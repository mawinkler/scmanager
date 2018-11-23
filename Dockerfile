FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y curl jq
RUN mkdir /app

COPY ./scmanager.sh /app
WORKDIR /app
RUN chmod +x /app/scmanager.sh

ENTRYPOINT ["/bin/bash", "-l", "-c"]
CMD ["scmanager.sh"]
