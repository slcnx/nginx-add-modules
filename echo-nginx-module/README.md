# 模块位置

[echo-nginx-module](https://github.com/openresty/echo-nginx-module/tags) from the [github](https://github.com/openresty/echo-nginx-module)

## 示例

```nginx
server {
    listen       80;
    server_name  liangcheng.mykernel.cn;
    location / {
           echo  ancient_browser  ----> $ancient_browser;
            echo  arg_  ----> $arg_;
            echo  args  ----> $args;
            echo  binary_remote_addr  ----> $binary_remote_addr;
            echo  binary_remote_addr  ----> $binary_remote_addr;
            echo  body_bytes_sent  ----> $body_bytes_sent;
            #echo  bytes_received  ----> $bytes_received;
            echo  bytes_sent  ----> $bytes_sent;
            echo  bytes_sent  ----> $bytes_sent;
            echo  bytes_sent  ----> $bytes_sent;
            echo  connection  ----> $connection;
            echo  connection  ----> $connection;
            echo  connection  ----> $connection;
            echo  connection_requests  ----> $connection_requests;
            echo  connection_requests  ----> $connection_requests;
            echo  connection_time  ----> $connection_time;
            echo  connections_active  ----> $connections_active;
            echo  connections_reading  ----> $connections_reading;
            echo  connections_waiting  ----> $connections_waiting;
            echo  connections_writing  ----> $connections_writing;
            echo  content_length  ----> $content_length;
            echo  content_type  ----> $content_type;
            echo  cookie_  ----> $cookie_;
            echo  date_gmt  ----> $date_gmt;
            echo  date_local  ----> $date_local;
            echo  document_root  ----> $document_root;
            echo  document_uri  ----> $document_uri;
            echo  fastcgi_path_info  ----> $fastcgi_path_info;
            echo  fastcgi_script_name  ----> $fastcgi_script_name;
            #echo  geoip_area_code  ----> $geoip_area_code;
            #echo  geoip_area_code  ----> $geoip_area_code;
            #echo  geoip_city  ----> $geoip_city;
            #echo  geoip_city  ----> $geoip_city;
            #echo  geoip_city_continent_code  ----> $geoip_city_continent_code;
            #echo  geoip_city_continent_code  ----> $geoip_city_continent_code;
            #echo  geoip_city_country_code  ----> $geoip_city_country_code;
            #echo  geoip_city_country_code  ----> $geoip_city_country_code;
            #echo  geoip_city_country_code3  ----> $geoip_city_country_code3;
            #echo  geoip_city_country_code3  ----> $geoip_city_country_code3;
            #echo  geoip_city_country_name  ----> $geoip_city_country_name;
            #echo  geoip_city_country_name  ----> $geoip_city_country_name;
            #echo  geoip_country_code  ----> $geoip_country_code;
            #echo  geoip_country_code  ----> $geoip_country_code;
            #echo  geoip_country_code3  ----> $geoip_country_code3;
            #echo  geoip_country_code3  ----> $geoip_country_code3;
            #echo  geoip_country_name  ----> $geoip_country_name;
            #echo  geoip_country_name  ----> $geoip_country_name;
            #echo  geoip_dma_code  ----> $geoip_dma_code;
            #echo  geoip_dma_code  ----> $geoip_dma_code;
            #echo  geoip_latitude  ----> $geoip_latitude;
            #echo  geoip_latitude  ----> $geoip_latitude;
            #echo  geoip_longitude  ----> $geoip_longitude;
            #echo  geoip_longitude  ----> $geoip_longitude;
            #echo  geoip_org  ----> $geoip_org;
            #echo  geoip_org  ----> $geoip_org;
            #echo  geoip_postal_code  ----> $geoip_postal_code;
            #echo  geoip_postal_code  ----> $geoip_postal_code;
            #echo  geoip_region  ----> $geoip_region;
            #echo  geoip_region  ----> $geoip_region;
            #echo  geoip_region_name  ----> $geoip_region_name;
            #echo  geoip_region_name  ----> $geoip_region_name;
            echo  gzip_ratio  ----> $gzip_ratio;
            echo  host  ----> $host;
            echo  hostname  ----> $hostname;
            echo  hostname  ----> $hostname;
            echo  http2  ----> $http2;
            echo  http_  ----> $http_;
            echo  https  ----> $https;
            echo  invalid_referer  ----> $invalid_referer;
            echo  is_args  ----> $is_args;
            #echo  jwt_claim_  ----> $jwt_claim_;
            #echo  jwt_header_  ----> $jwt_header_;
            #echo  jwt_payload  ----> $jwt_payload;
            echo  limit_conn_status  ----> $limit_conn_status;
            echo  limit_conn_status  ----> $limit_conn_status;
            echo  limit_rate  ----> $limit_rate;
            echo  limit_req_status  ----> $limit_req_status;
            #echo  memcached_key  ----> $memcached_key;
            echo  modern_browser  ----> $modern_browser;
            echo  msec  ----> $msec;
            echo  msec  ----> $msec;
            echo  msec  ----> $msec;
            echo  msie  ----> $msie;
            echo  nginx_version  ----> $nginx_version;
            echo  nginx_version  ----> $nginx_version;
            echo  pid  ----> $pid;
            echo  pid  ----> $pid;
            echo  pipe  ----> $pipe;
            echo  pipe  ----> $pipe;
            #echo  protocol  ----> $protocol;
            echo  proxy_add_x_forwarded_for  ----> $proxy_add_x_forwarded_for;
            echo  proxy_host  ----> $proxy_host;
            echo  proxy_port  ----> $proxy_port;
            echo  proxy_protocol_addr  ----> $proxy_protocol_addr;
            echo  proxy_protocol_addr  ----> $proxy_protocol_addr;
            echo  proxy_protocol_port  ----> $proxy_protocol_port;
            echo  proxy_protocol_port  ----> $proxy_protocol_port;
            echo  proxy_protocol_server_addr  ----> $proxy_protocol_server_addr;
            echo  proxy_protocol_server_addr  ----> $proxy_protocol_server_addr;
            echo  proxy_protocol_server_port  ----> $proxy_protocol_server_port;
            echo  proxy_protocol_server_port  ----> $proxy_protocol_server_port;
            echo  query_string  ----> $query_string;
            echo  realip_remote_addr  ----> $realip_remote_addr;
            echo  realip_remote_addr  ----> $realip_remote_addr;
            echo  realip_remote_port  ----> $realip_remote_port;
            echo  realip_remote_port  ----> $realip_remote_port;
            echo  realpath_root  ----> $realpath_root;
            echo  remote_addr  ----> $remote_addr;
            echo  remote_addr  ----> $remote_addr;
            echo  remote_port  ----> $remote_port;
            echo  remote_port  ----> $remote_port;
            echo  remote_user  ----> $remote_user;
            echo  request  ----> $request;
            echo  request_body  ----> $request_body;
            echo  request_body_file  ----> $request_body_file;
            echo  request_completion  ----> $request_completion;
            echo  request_filename  ----> $request_filename;
            echo  request_id  ----> $request_id;
            echo  request_length  ----> $request_length;
            echo  request_length  ----> $request_length;
            echo  request_method  ----> $request_method;
            echo  request_time  ----> $request_time;
            echo  request_time  ----> $request_time;
            echo  request_uri  ----> $request_uri;
            echo  scheme  ----> $scheme;
            echo  secure_link  ----> $secure_link;
            echo  secure_link_expires  ----> $secure_link_expires;
            echo  sent_http_  ----> $sent_http_;
            echo  sent_trailer_  ----> $sent_trailer_;
            echo  server_addr  ----> $server_addr;
            echo  server_addr  ----> $server_addr;
            echo  server_name  ----> $server_name;
            echo  server_port  ----> $server_port;
            echo  server_port  ----> $server_port;
            echo  server_protocol  ----> $server_protocol;
            #echo  session_log_binary_id  ----> $session_log_binary_id;
            #echo  session_log_id  ----> $session_log_id;
            #echo  session_time  ----> $session_time;
            echo  slice_range  ----> $slice_range;
            #echo  spdy  ----> $spdy;
            #echo  spdy_request_priority  ----> $spdy_request_priority;
            #echo  ssl_alpn_protocol  ----> $ssl_alpn_protocol;
            #echo  ssl_alpn_protocol  ----> $ssl_alpn_protocol;
            #echo  ssl_cipher  ----> $ssl_cipher;
            #echo  ssl_cipher  ----> $ssl_cipher;
            #echo  ssl_ciphers  ----> $ssl_ciphers;
            #echo  ssl_ciphers  ----> $ssl_ciphers;
            #echo  ssl_client_cert  ----> $ssl_client_cert;
            #echo  ssl_client_cert  ----> $ssl_client_cert;
            #echo  ssl_client_escaped_cert  ----> $ssl_client_escaped_cert;
            #echo  ssl_client_fingerprint  ----> $ssl_client_fingerprint;
            #echo  ssl_client_fingerprint  ----> $ssl_client_fingerprint;
            #echo  ssl_client_i_dn  ----> $ssl_client_i_dn;
            #echo  ssl_client_i_dn  ----> $ssl_client_i_dn;
            #echo  ssl_client_i_dn_legacy  ----> $ssl_client_i_dn_legacy;
            #echo  ssl_client_raw_cert  ----> $ssl_client_raw_cert;
            #echo  ssl_client_raw_cert  ----> $ssl_client_raw_cert;
            #echo  ssl_client_s_dn  ----> $ssl_client_s_dn;
            #echo  ssl_client_s_dn  ----> $ssl_client_s_dn;
            #echo  ssl_client_s_dn_legacy  ----> $ssl_client_s_dn_legacy;
            #echo  ssl_client_serial  ----> $ssl_client_serial;
            #echo  ssl_client_serial  ----> $ssl_client_serial;
            #echo  ssl_client_v_end  ----> $ssl_client_v_end;
            #echo  ssl_client_v_end  ----> $ssl_client_v_end;
            #echo  ssl_client_v_remain  ----> $ssl_client_v_remain;
            #echo  ssl_client_v_remain  ----> $ssl_client_v_remain;
            #echo  ssl_client_v_start  ----> $ssl_client_v_start;
            #echo  ssl_client_v_start  ----> $ssl_client_v_start;
            #echo  ssl_client_verify  ----> $ssl_client_verify;
            #echo  ssl_client_verify  ----> $ssl_client_verify;
            #echo  ssl_curve  ----> $ssl_curve;
            #echo  ssl_curve  ----> $ssl_curve;
            #echo  ssl_curves  ----> $ssl_curves;
            #echo  ssl_curves  ----> $ssl_curves;
            #echo  ssl_early_data  ----> $ssl_early_data;
            #echo  ssl_preread_alpn_protocols  ----> $ssl_preread_alpn_protocols;
            #echo  ssl_preread_protocol  ----> $ssl_preread_protocol;
            #echo  ssl_preread_server_name  ----> $ssl_preread_server_name;
            #echo  ssl_protocol  ----> $ssl_protocol;
            #echo  ssl_protocol  ----> $ssl_protocol;
            #echo  ssl_server_name  ----> $ssl_server_name;
            #echo  ssl_server_name  ----> $ssl_server_name;
            #echo  ssl_session_id  ----> $ssl_session_id;
            #echo  ssl_session_id  ----> $ssl_session_id;
            #echo  ssl_session_reused  ----> $ssl_session_reused;
            #echo  ssl_session_reused  ----> $ssl_session_reused;
            echo  status  ----> $status;
            echo  status  ----> $status;
            echo  status  ----> $status;
            echo  tcpinfo_rtt  ----> $tcpinfo_rtt;
            echo  tcpinfo_rttvar  ----> $tcpinfo_rttvar;
            echo  tcpinfo_snd_cwnd  ----> $tcpinfo_snd_cwnd;
            echo  tcpinfo_rcv_space  ----> $tcpinfo_rcv_space;
            echo  time_iso8601  ----> $time_iso8601;
            echo  time_iso8601  ----> $time_iso8601;
            echo  time_iso8601  ----> $time_iso8601;
            echo  time_local  ----> $time_local;
            echo  time_local  ----> $time_local;
            echo  time_local  ----> $time_local;
            echo  uid_got  ----> $uid_got;
            echo  uid_reset  ----> $uid_reset;
            echo  uid_set  ----> $uid_set;
            #echo  upstream_addr  ----> $upstream_addr;
            #echo  upstream_addr  ----> $upstream_addr;
            #echo  upstream_bytes_received  ----> $upstream_bytes_received;
            #echo  upstream_bytes_received  ----> $upstream_bytes_received;
            #echo  upstream_bytes_sent  ----> $upstream_bytes_sent;
            #echo  upstream_bytes_sent  ----> $upstream_bytes_sent;
            #echo  upstream_cache_status  ----> $upstream_cache_status;
            #echo  upstream_connect_time  ----> $upstream_connect_time;
            #echo  upstream_connect_time  ----> $upstream_connect_time;
            #echo  upstream_cookie_  ----> $upstream_cookie_;
            #echo  upstream_first_byte_time  ----> $upstream_first_byte_time;
            #echo  upstream_header_time  ----> $upstream_header_time;
            #echo  upstream_http_  ----> $upstream_http_;
            #echo  upstream_queue_time  ----> $upstream_queue_time;
            #echo  upstream_response_length  ----> $upstream_response_length;
            #echo  upstream_response_time  ----> $upstream_response_time;
            #echo  upstream_session_time  ----> $upstream_session_time;
            #echo  upstream_status  ----> $upstream_status;
            #echo  upstream_trailer_  ----> $upstream_trailer_;
            echo  uri  ----> $uri;
    }
    location /echo {
        echo_after_body after echo;
        echo_before_body before echo;
        echo_before_body proxy_pass http://127.0.0.1:$server_port$uri/more;
        proxy_pass http://127.0.0.1:$server_port$uri/more;
    }
    location /echo/more {
        echo more;
    }
}
```

## 验证通用代理

```bash
curl 'localhost/1?k=v&k1=v1'
```

```bash
ancient_browser ----> 1
arg_ ---->
args ----> k=v&k1=v1
binary_remote_addr ---->
binary_remote_addr ---->
body_bytes_sent ----> 0
bytes_sent ----> 0
bytes_sent ----> 0
bytes_sent ----> 0
connection ----> 15417
connection ----> 15417
connection ----> 15417
connection_requests ----> 1
connection_requests ----> 1
connection_time ----> 0.000
connections_active ----> 1
connections_reading ----> 0
connections_waiting ----> 0
connections_writing ----> 1
content_length ---->
content_type ---->
cookie_ ---->
date_gmt ----> Wednesday, 05-Jan-2022 06:47:25 GMT
date_local ----> Wednesday, 05-Jan-2022 14:47:25 CST
document_root ----> /etc/nginx/html
document_uri ----> /1
fastcgi_path_info ---->
fastcgi_script_name ----> /1
gzip_ratio ---->
host ----> localhost
hostname ----> localhost.localdomain
hostname ----> localhost.localdomain
http2 ---->
http_ ---->
https ---->
invalid_referer ---->
is_args ----> ?
limit_conn_status ---->
limit_conn_status ---->
limit_rate ----> 0
limit_req_status ---->
modern_browser ---->
msec ----> 1641365245.810
msec ----> 1641365245.810
msec ----> 1641365245.810
msie ---->
nginx_version ----> 1.20.2
nginx_version ----> 1.20.2
pid ----> 22999
pid ----> 22999
pipe ----> .
pipe ----> .
proxy_add_x_forwarded_for ----> 127.0.0.1
proxy_host ---->
proxy_port ---->
proxy_protocol_addr ---->
proxy_protocol_addr ---->
proxy_protocol_port ---->
proxy_protocol_port ---->
proxy_protocol_server_addr ---->
proxy_protocol_server_addr ---->
proxy_protocol_server_port ---->
proxy_protocol_server_port ---->
query_string ----> k=v&k1=v1
realip_remote_addr ----> 127.0.0.1
realip_remote_addr ----> 127.0.0.1
realip_remote_port ----> 52500
realip_remote_port ----> 52500
realpath_root ---->
remote_addr ----> 127.0.0.1
remote_addr ----> 127.0.0.1
remote_port ----> 52500
remote_port ----> 52500
remote_user ---->
request ----> GET /1?k=v&k1=v1 HTTP/1.1
request_body ---->
request_body_file ---->
request_completion ---->
request_filename ----> /etc/nginx/html/1
request_id ----> 816e88869112526afa67394d89cbf2f4
request_length ----> 84
request_length ----> 84
request_method ----> GET
request_time ----> 0.000
request_time ----> 0.000
request_uri ----> /1?k=v&k1=v1
scheme ----> http
secure_link ---->
secure_link_expires ---->
sent_http_ ---->
sent_trailer_ ---->
server_addr ----> 127.0.0.1
server_addr ----> 127.0.0.1
server_name ----> liangcheng.mykernel.cn
server_port ----> 80
server_port ----> 80
server_protocol ----> HTTP/1.1
slice_range ---->
status ----> 200
status ----> 200
status ----> 200
tcpinfo_rtt ----> 4
tcpinfo_rttvar ----> 1
tcpinfo_snd_cwnd ----> 10
tcpinfo_rcv_space ----> 43690
time_iso8601 ----> 2022-01-05T14:47:25+08:00
time_iso8601 ----> 2022-01-05T14:47:25+08:00
time_iso8601 ----> 2022-01-05T14:47:25+08:00
time_local ----> 05/Jan/2022:14:47:25 +0800
time_local ----> 05/Jan/2022:14:47:25 +0800
time_local ----> 05/Jan/2022:14:47:25 +0800
uid_got ---->
uid_reset ---->
uid_set ---->
uri ----> /1
```



## proxy_pass

```bash
[root@localhost ~]# curl 'localhost/echo'
before echo
proxy_pass http://127.0.0.1:80/echo/more
more
after echo
[root@localhost ~]# curl 'localhost/echo?k=v'
before echo
proxy_pass http://127.0.0.1:80/echo/more
more
after echo
```

