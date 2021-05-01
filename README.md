# nginx-auth-saslauthd

Nginx authentication module support for LDAP, PAM or other mechanisms
supported by saslauthd. Authentication requests are forwarded from nginx
to a running saslauthd using its unix domain socket.

```nginx
location /restricted/ {
	auth_saslauthd "restricted area";
	auth_saslauthd_socket /var/run/saslauthd/mux;
}
```

## Installation

**This module has not (yet?) been packaged**. That means that you must know
how to compile and install it (see nginx doc), compilation and installation
is done as any 3rd party nginx module. Be sure to use the same nginx version,
with e.g. `git checkout release-1.18.0`.

As an example, I use this (simplified) commands to build on Alpine, from the
nginx source code directory:

```bash
apk add linux-headers make gcc musl-dev libaio-dev pcre-dev openssl-dev zlib-dev libxslt-dev gd-dev geoip-dev perl-dev
auto/configure --add-dynamic-module=/path/to/nginx-auth-saslauthd --prefix=/var/lib/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --pid-path=/run/nginx/nginx.pid --lock-path=/run/nginx/nginx.lock --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --with-perl_modules_path=/usr/lib/perl5/vendor_perl --user=nginx --group=nginx --with-threads --with-file-aio --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-mail=dynamic --with-mail_ssl_module --with-stream=dynamic --with-stream_ssl_module --with-stream_realip_module --with-stream_geoip_module=dynamic --with-stream_ssl_preread_module
make -j modules
strip objs/ngx_http_auth_saslauthd_module.so
```

## Support and documentation

```
man rickroll
```

## Licenses and Copyrights

© 2021 Alexandre Jousset

This program is free software; you can redistribute and modify it under the
terms of the *BSD-2-Clause License*.

Based on some code from
[Cyrus-SASL](https://github.com/cyrusimap/cyrus-sasl/blob/master/saslauthd/testsaslauthd.c) (see LICENSE.cyrus)
and
[Nginx](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c) (see LICENSE.nginx).
