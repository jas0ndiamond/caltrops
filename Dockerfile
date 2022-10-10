FROM debian:buster-20220316
MAINTAINER jason.a.diamond@gmail.com

#run this in a privileged container - iptables is a privileged feature
#docker run --name caltrops --privileged=true -p 5000:5000 -p 3128-3148:3128-3148 jas0ndiamond/caltrops

RUN mkdir /opt/caltrops

#core os setup
RUN /usr/bin/apt-get -y update
RUN /usr/bin/apt-get -y upgrade
RUN /usr/bin/apt-get -y install apt-utils readline-common libterm-readline-gnu-perl libreadline-dev

#os setup for python3 and its depos
#python depos for compilation, excessive and borrowed from another project

RUN /usr/bin/apt-get -y install python3 python3-pip gcc g++ make automake autoconf build-essential apache2-utils git g++-multilib libssl-dev libssl1.1 zlib1g-dev build-essential libffi-dev libbz2-dev libncursesw5-dev libgdbm-dev liblzma-dev libsqlite3-dev tk-dev uuid-dev libreadline-dev python3 python3-dev libgdbm-compat-dev libjpeg-dev zlib1g-dev apache-tools procps iptables squid

#clean up apt
RUN /usr/bin/apt-get clean && rm -rf /var/lib/apt/lists

#debug tools
#RUN /usr/bin/apt-get -y install nano vim telnet

RUN /usr/bin/python3 -V

#python setup - upgrade pip and install core packages
RUN /usr/bin/python3 -m pip install --upgrade pip
RUN /usr/bin/python3 -m pip install wheel

#iptables
RUN /usr/bin/python3 -m pip install python-iptables flask

#####################
#squid config - 4.8

#squid can't be run as root or it will cause problems
#set ownership and permissions for the "proxy" user and
#group that are added by installing squid from the
#package manager above

#copy our config
COPY squid.conf /etc/squid/squid.conf
RUN chown proxy:proxy /etc/squid/squid.conf

#create squid log dir
RUN mkdir -p /var/log/squid
RUN chmod 775 /var/log/squid
RUN chown proxy:proxy /var/log/squid

#create squid cache
RUN mkdir /var/cache/squid
RUN chmod 775 /var/cache/squid
RUN chown proxy:proxy /var/cache/squid

#create squid pid dir
RUN mkdir /var/run/squid

RUN chmod 775 /var/run/squid
RUN chown proxy:proxy /var/run/squid

#setup our user
RUN /usr/bin/htpasswd -b -c /etc/squid/passwd_basic myproxyuser myproxypass
RUN chown proxy:proxy /etc/squid/passwd_basic

#########
#more squid config, as the proxy user

#switch to the non-root user squid will run as
USER proxy

#generate squid cache
#may complain about "non-functional IPv6 loopback". I think this can be ignored.
RUN /usr/sbin/squid -N -f /etc/squid/squid.conf -z

#squid config check
RUN /usr/sbin/squid -k parse

#squid technically ready to run at this point, but will
#run as part of the entrypoint shell script

###############
#ports

#flask hw port
EXPOSE 5000

#proxy ports for edge devices. synchronize with the allowed ports in the squid config
EXPOSE 3128-3148

################
#deploy our flask app

#switch back to root- have to run as root for iptables
#root also owns /opt/ by default
USER root

COPY caltrops.py /opt/caltrops/caltrops.py

#create caltrops web dir for ui resources
RUN mkdir /opt/caltrops/www

#copy ui resources to flask www directory
COPY res/www/ /opt/caltrops/www

################
#run the caltrops app as the container entrypoint

COPY entrypoint.sh /opt/caltrops/entrypoint.sh



ENTRYPOINT /bin/bash /opt/caltrops/entrypoint.sh
