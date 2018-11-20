FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y curl jq
RUN mkdir /app

COPY ./scmanager.sh /app
WORKDIR /app

ENTRYPOINT ["/bin/bash"]
CMD ["scmanager.sh"]
