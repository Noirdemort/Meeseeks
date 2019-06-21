FROM mongo:latest
RUN apt-get update -y --fix-missing
RUN apt-get install gnupg2 -y
RUN apt-get install -y python3-pip build-essential libssl-dev libffi-dev python3-dev
RUN apt-get install systemd -y
EXPOSE 27017
EXPOSE 5000
RUN alias python=python3
VOLUME /data/db
RUN apt-get install -y mongodb
RUN chmod +x /etc/init.d/mongodb
RUN mongod &
RUN python3 -m pip install --upgrade pip
RUN mkdir -p /usr/src/windfarm
RUN service mongodb start
WORKDIR /usr/src/windfarm
COPY . .
RUN ls
RUN pwd
RUN python3 -m pip install -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["app.py"]