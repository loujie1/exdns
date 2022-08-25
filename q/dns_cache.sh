

root="a."
l1="a.l1."
l2="a.l2.l1."
l3="a.l3.l2.l1."
l4="a.l4.l3.l2.l1."
l5="a.l5.l4.l3.l2.l1."
l6="a.l6.l5.l4.l3.l2.l1."
l7="a.l7.l6.l5.l4.l3.l2.l1."
l8="a.l8.l7.l6.l5.l4.l3.l2.l1."



queryRoot(){
  ./q -port 53 @@64.227.123.153 $root
}

queryL1(){
  ./q -port 53 @@64.227.123.153 $l1
}

queryL2(){
  ./q -port 53 -output="${1:-""}" -chain="3" @64.227.123.153 $l2
}

queryL3(){
  ./q -port 53 -output="${1:-""}" -chain="4" @@64.227.123.153 $l3
}

queryL4(){
  ./q -port 53 -output="${1:-""}" -chain="5" @@64.227.123.153 $l4
}

queryL5(){
  ./q -port 53 -output="${1:-""}" -chain="6" @@64.227.123.153 $l5
}

queryL6(){
  ./q -port 53 -output="${1:-""}" -chain="7" @@64.227.123.153 $l6
}

createCache(){
  queryL2 &
  queryL3 &
  queryL4 &
  queryL5 &
  queryL6 &
  wait
}

queryAllCached(){
  queryL2 ./len_3_cache_dns.csv &
  queryL3 ./len_4_cache_dns.csv &
  queryL4 ./len_5_cache_dns.csv &
  queryL5 ./len_6_cache_dns.csv &
  queryL6 ./len_7_cache_dns.csv &
  wait
}
#for qname in "a." "a.l1." "a.l2.l1.l2.l1." "a.l3.l2.l1.l3.l2.l1." "a.l4.l3.l2.l1." "a.l5.l4.l3.l2.l1." "a.l6.l5.l4.l3.l2.l1." "a.l7.l6.l5.l4.l3.l2.l1." "a.l8.l7.l6.l5.l4.l3.l2.l1.";do ./q -port 53 -rhine -cert=./testdata/certificate/CACert.pem @@64.227.123.153 $qname; done
#queryWithoutCache(){
#
#}
queryWithCache(){
  for run in {1..5}; do createCache; done
  for run in {1..100}; do queryAllCached; done
}

queryAllNoCache(){
  queryL2 ./len_3_no_cache_dns.csv
  sleep 3
  queryL3 ./len_4_no_cache_dns.csv
  sleep 3
  queryL4 ./len_5_no_cache_dns.csv
  sleep 3
  queryL5 ./len_6_no_cache_dns.csv
  sleep 3
  queryL6 ./len_7_no_cache_dns.csv
  sleep 3
}
queryWithoutCache(){
  for run in {1..100}; do queryAllNoCache; done
}

queryWithCache