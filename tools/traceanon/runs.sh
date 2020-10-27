#!/bin/bash

clear
#make && ./traceanon --radius-salt='this is my salt' --radius-server=203.114.128.111:1645:27910:28166 ../../../example/trace/radius-one.erf.gz erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf
#traceanon ../../../example/trace/radius-openli.erf.gz erf:../../../example/trace/example.erf 

#runs trace anon on jsut one packet
#make && ./traceanon -s -c=012345678901234567890123456789ab --radius-server=203.114.128.111:1645 ../../../example/trace/radius-one.erf.gz erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf

make && ./traceanon -sd -c foobarbazaaaaaaaaaaaaaaaaaaaaaaaaaaaa ../../../example/trace/radius-openli.erf.gz -R saltysalt -r 203.114.128.111:1645:1646 erf:../../../example/trace/example-all.erf
#make && ./traceanon -sd -c foobarbazaaaaaaaaaaaaaaaaaaaaaaaaaaaa ../../../example/trace/radius-one.erf.gz -R saltysalt -r 203.114.128.111:1645:1646 erf:../../../example/trace/example.erf && tracepktdump ../../../example/trace/example.erf