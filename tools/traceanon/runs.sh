#!/bin/bash

clear
make && ./traceanon --radius-server=203.114.128.111:1645 ../../../example/trace/radius-one.erf.gz erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf
<<<<<<< HEAD
#traceanon ../../../example/trace/radius-openli.erf.gz erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf
=======
traceanon ../../../example/trace/radius-openli.erf.gz erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf
>>>>>>> c90c6b81811e29b200424724cfbbb8c583297ca4
