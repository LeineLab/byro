FROM python:3.10.16
LABEL org.opencontainers.image.authors="byro team"

EXPOSE 8020

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y zsh gettext libjpeg-dev libmagic-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd uid1000 -d /home/uid1000
RUN mkdir -p /home/uid1000 && chown uid1000: /home/uid1000
RUN mkdir -p /byro && chown uid1000: /byro

ADD . /byro
ADD byro.docker.cfg /byro/byro.cfg
WORKDIR /byro 
RUN   pip install --upgrade pip && pip3 install -e . && pip3 install gunicorn
RUN  /bin/zsh install_local_plugins.sh

CMD ["runserver", "0.0.0.0:8020"]

WORKDIR /byro
ENTRYPOINT ["/usr/bin/env", "python3", "manage.py"]
