#!/bin/sh
# 
# This is a nasty script that I use to test auth using a real ejabberd installation (;
#
# docker run -it -v $(pwd):/ejabberd-auth-jwt -p 5280:5280 -p 5222:5222 --entrypoint /bin/sh ejabberd/ecs:18.06 /ejabberd-auth-jwt/setup.sh
set -e

mkdir -p ~/.ejabberd-modules/sources/
cp -R /ejabberd-auth-jwt ~/.ejabberd-modules/sources/ejabberd_auth_jwt
bin/ejabberdctl start
sleep 6
bin/ejabberdctl module_install ejabberd_auth_jwt
bin/ejabberdctl stop
sleep 3
bin/ejabberdctl foreground
