
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t   socket;
} ngx_http_auth_saslauthd_loc_conf_t;

static ngx_int_t  ngx_http_auth_saslauthd_handler(ngx_http_request_t *r);
static ngx_int_t  ngx_http_auth_saslauthd_set_realm(ngx_http_request_t *r, ngx_str_t *realm);
static void      *ngx_http_auth_saslauthd_create_loc_conf(ngx_conf_t *cf);
static char      *ngx_http_auth_saslauthd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t  ngx_http_auth_saslauthd_init(ngx_conf_t *cf);
static char      *ngx_http_auth_saslauthd_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_auth_saslauthd_commands[] = {
    { ngx_string("auth_saslauthd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_saslauthd_loc_conf_t, realm),
      NULL },

    { ngx_string("auth_saslauthd_socket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_saslauthd_socket,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_saslauthd_loc_conf_t, socket),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_saslauthd_module_ctx = {
    NULL,                                      /* preconfiguration */
    ngx_http_auth_saslauthd_init,              /* postconfiguration */

    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    ngx_http_auth_saslauthd_create_loc_conf,   /* create location configuration */
    ngx_http_auth_saslauthd_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_saslauthd_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_saslauthd_module_ctx,       /* module context */
    ngx_http_auth_saslauthd_commands,          /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};


/**************************************************************
 * I/O wrapper to attempt to write out the specified vector.
 * data, without any guarantees. If the function returns
 * -1, the vector wasn't completely written.
 **************************************************************/
static int
retry_writev(int fd, struct iovec *iov, int iovcnt) {
    int n;               /* return value from writev() */
    int i;               /* loop counter */
    int written;         /* bytes written so far */
    static int iov_max;  /* max number of iovec entries */

    iov_max = IOV_MAX;

    written = 0;

    for (;;) {

        while (iovcnt && iov[0].iov_len == 0) {
            iov++;
            iovcnt--;
        }

        if (!iovcnt) {
            return written;
        }

        n = writev(fd, iov, iovcnt > iov_max ? iov_max : iovcnt);

        if (n == -1) {
            if (errno == EINVAL && iov_max > 10) {
                iov_max /= 2;
                continue;
            }

            if (errno == EINTR) {
                continue;
            }

            return -1;

        } else {
            written += n;
        }

        for (i = 0; i < iovcnt; i++) {
            if ((int) iov[i].iov_len > n) {
                iov[i].iov_base = (char *)iov[i].iov_base + n;
                iov[i].iov_len -= n;
                break;
            }

            n -= iov[i].iov_len;
            iov[i].iov_len = 0;
        }

        if (i == iovcnt) {
            return written;
        }
    }
}


/*
 * Keep calling the read() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is read in or an error occurs.
 */
static int
retry_read(int fd, void *inbuf, unsigned nbyte)
{
    int n;
    int nread = 0;
    char *buf = (char *)inbuf;

    if (nbyte == 0) return 0;

    for (;;) {
        n = ngx_read_fd(fd, buf, nbyte);
        if (n == -1 || n == 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }

        nread += n;

        if (n >= (int) nbyte) return nread;

        buf += n;
        nbyte -= n;
    }
}


/* saslauthd-authenticated login */
static ngx_int_t
saslauthd_verify_password(
    ngx_http_request_t *req,
    const ngx_str_t    *sck,
    const ngx_str_t    *userid,
    const ngx_str_t    *passwd,
    const ngx_str_t    *service,
    const ngx_str_t    *user_realm,
    const ngx_str_t    *client_addr)
{
    u_char response[1024];
    u_char query[8192];
    u_char *query_end = query;
    ngx_socket_t s;
    int r;
    unsigned short count;
    struct sockaddr_un srvaddr;
    ngx_str_t null_str = ngx_null_string;

    if(!userid || !passwd) return NGX_DECLINED;
    if(!service) service = &null_str;
    if(!user_realm) user_realm = &null_str;
    if(!client_addr) client_addr = &null_str;

    if(!sck)
        return NGX_ERROR;

    if (sck->len + 1 > sizeof(srvaddr.sun_path))
        return NGX_ERROR;

    if (userid->len + passwd->len + service->len + user_realm->len + client_addr->len + 5 * sizeof(unsigned short) > sizeof(query))
        return NGX_ERROR;

    /*
     * build request of the form:
     *
     * count authid count password count service count realm
     */
    {
        unsigned short u_len, p_len, s_len, r_len, c_len;

        u_len = htons(userid->len);
        p_len = htons(passwd->len);
        s_len = htons(service->len);
        r_len = htons(user_realm->len);
        c_len = htons(client_addr->len);

        ngx_memcpy(query_end, &u_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        ngx_memcpy(query_end, userid->data, userid->len);
        query_end += userid->len;

        ngx_memcpy(query_end, &p_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        ngx_memcpy(query_end, passwd->data, passwd->len);
        query_end += passwd->len;

        ngx_memcpy(query_end, &s_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        ngx_memcpy(query_end, service->data, service->len);
        query_end += service->len;

        ngx_memcpy(query_end, &r_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        ngx_memcpy(query_end, user_realm->data, user_realm->len);
        query_end += user_realm->len;

        ngx_memcpy(query_end, &c_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        ngx_memcpy(query_end, client_addr->data, client_addr->len);
        query_end += client_addr->len;
    }

    s = ngx_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    ngx_memcpy(srvaddr.sun_path, sck->data, sck->len + 1);

    r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
    if (r == -1) {
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      "connect() failed");
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    {
        struct iovec iov[8];

        iov[0].iov_len = query_end - query;
        iov[0].iov_base = query;

        if (retry_writev(s, iov, 1) == -1) {
            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_ERROR;
        }

    }

    /*
     * read response of the form:
     *
     * count result
     */
    if (retry_read(s, &count, sizeof(count)) < (int) sizeof(count)) {
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      "size read failed\n");
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    count = ntohs(count);
    if (count < 2) { /* MUST have at least "OK" or "NO" */
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      "bad response from saslauthd\n");
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    count = (int)sizeof(response) < count ? sizeof(response) : count;
    if (retry_read(s, response, count) < count) {
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      "read failed\n");
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }
    response[count] = '\0';

    if (ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, req->connection->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (!ngx_strncmp(response, "OK", 2))
        return NGX_OK;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_auth_saslauthd_handler(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_str_t                           realm, sck;
    ngx_http_auth_saslauthd_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_saslauthd_module);

    if (alcf->realm == NULL || alcf->socket.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return ngx_http_auth_saslauthd_set_realm(r, &realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, &alcf->socket, &sck) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = saslauthd_verify_password(
        r,
        &sck,
        &r->headers_in.user,
        &r->headers_in.passwd,
        NULL,
        NULL,
        NULL);

    if (rc != NGX_OK)
        return ngx_http_auth_saslauthd_set_realm(r, &realm);

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_saslauthd_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}


static void *
ngx_http_auth_saslauthd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_saslauthd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_saslauthd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_saslauthd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_saslauthd_loc_conf_t  *prev = parent;
    ngx_http_auth_saslauthd_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->socket.value.data == NULL) {
        conf->socket = prev->socket;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_saslauthd_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_saslauthd_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_saslauthd_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_saslauthd_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->socket.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->socket;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
