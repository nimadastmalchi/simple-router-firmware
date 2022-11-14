FROM ubuntu:xenial

ARG DEBIAN_FRONTEND=noninteractive

# Install basic dependencies
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential vim-nox emacs apt-utils net-tools
RUN apt-get -y install git python-dev python-setuptools flex bison traceroute libbz2-dev libssl-dev python-pip
RUN apt-get -y install mininet expect inetutils-ping
RUN apt-get -y install xauth
RUN apt-get -y install libzeroc-ice35-dev libboost-all-dev

# Install POX controller
RUN rm -Rf /opt/pox
RUN mkdir -p /opt/pox
RUN git clone -b eel https://github.com/noxrepo/pox /opt/pox
ENV PYTHONPATH=":/opt/pox/"

# Copy the project directory
ADD . /

# Install packet redirector
RUN pip install ucla-cs118

# Set up for start
RUN service openvswitch-switch start
CMD /bin/bash