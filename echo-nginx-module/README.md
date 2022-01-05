# 模块位置

[echo-nginx-module](https://github.com/openresty/echo-nginx-module/tags) from the [github](https://github.com/openresty/echo-nginx-module)



```nginx
server {
    listen       80;
    server_name  localhost;

    #access_log  /var/log/nginx/host.access.log  main;

    location / {
        set $opt world==;
        echo "hello $opt";
        echo The current request uri is $request_uri;
        echo ==============;
        echo_duplicate 1 $echo_client_request_headers;
        echo "\r";
        echo_read_request_body;
        echo $request_body;
    }
}
```

> ```bash
> [root@localhost ~]# curl -H 'host:www.baidu.com' -XPOST --data 'x=y' localhost
> hello world==
> The current request uri is /
> ==============
> POST / HTTP/1.1
> User-Agent: curl/7.29.0
> Accept: */*
> host:www.baidu.com
> Content-Length: 3
> Content-Type: application/x-www-form-urlencoded
> 
> 
> x=y
> ```



