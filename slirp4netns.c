#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>

#include "qemu/slirp/slirp.h"
#include "libslirp.h"
#include "parson/parson.h"

struct libslirp_data {
	int tapfd;
};

void slirp_output(void *opaque, const uint8_t * pkt, int pkt_len)
{
	struct libslirp_data *data = (struct libslirp_data *)opaque;
	int rc;
	if ((rc = write(data->tapfd, pkt, pkt_len)) < 0) {
		perror("slirp_output: write");
	}
	assert(rc == pkt_len);
}

Slirp *create_slirp(void *opaque, unsigned int mtu, bool ip6_enabled)
{
	Slirp *slirp = NULL;
	struct in_addr vnetwork, vnetmask, vhost, vdhcp_start, vnameserver;
	struct in6_addr vhost6, vprefix_addr6, vnameserver6;
	int vprefix_len = 64;
	inet_pton(AF_INET, "10.0.2.0", &vnetwork);
	inet_pton(AF_INET, "255.255.255.0", &vnetmask);
	inet_pton(AF_INET, "10.0.2.2", &vhost);
	inet_pton(AF_INET, "10.0.2.3", &vnameserver);
	inet_pton(AF_INET, "10.0.2.15", &vdhcp_start);
	inet_pton(AF_INET6, "fd00::2", &vhost6);
	inet_pton(AF_INET6, "fd00::", &vprefix_addr6);
	inet_pton(AF_INET6, "fd00::3", &vnameserver6);
	slirp = slirp_init(0 /* restricted */ , 1 /* is_enabled */ ,
			   vnetwork, vnetmask, vhost, (int)ip6_enabled, vprefix_addr6, vprefix_len, vhost6,
			   NULL /* vhostname */ , NULL /* bootfile */ , vdhcp_start,
			   vnameserver, vnameserver6, NULL /* vdnssearch */ , NULL /* vdomainname */ ,
			   mtu /* if_mtu */ , mtu /* if_mru */ ,
			   opaque);
	if (slirp == NULL) {
		fprintf(stderr, "slirp_init failed\n");
	}
	return slirp;
}

static int api_bindlisten(const char *api_socket)
{
	int fd;
	struct sockaddr_un addr;
	unlink(api_socket);	/* avoid EADDRINUSE */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("api_bindlisten: socket");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, api_socket, sizeof(addr.sun_path) - 1);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("api_bindlisten: bind");
		return -1;
	}
	if (listen(fd, 0) < 0) {
		perror("api_bindlisten: listen");
		return -1;
	}
	return fd;
}

struct api_ctx {
	uint8_t *buf;
	size_t buflen;
};

static struct api_ctx *api_ctx_alloc(void)
{
	struct api_ctx *ctx = (struct api_ctx *)malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->buflen = 4096;
	ctx->buf = malloc(ctx->buflen);	/* FIXME: realloc */
	if (ctx->buf == NULL) {
		return NULL;
	}
	return ctx;
}

static void api_ctx_free(struct api_ctx *ctx)
{
	if (ctx != NULL) {
		if (ctx->buf != NULL) {
			free(ctx->buf);
		}
		free(ctx);
	}
}

const char *api_ok = "{\"return\":{}}";

/*
  Handler for add_hostfwd.
  e.g. {"execute": "add_hostfwd", "arguments": {"proto": "tcp", "host_addr": "0.0.0.0", "host_port": 8080, "guest_addr": "10.0.2.100", "guest_port": 80}}
  This function returns the return value of write(2), not the return value of slirp_add_hostfwd().
 */
static int api_handle_req_add_hostfwd(Slirp * slirp, int fd, struct api_ctx *ctx, JSON_Object *jo)
{
	int wrc = 0, slirprc = 0;
	struct in_addr host_addr, guest_addr;
	int is_udp = -1;	/* TODO: support SCTP */
	const char *proto_s = json_object_dotget_string(jo, "arguments.proto");
	const char *host_addr_s = json_object_dotget_string(jo, "arguments.host_addr");
	int host_port = (int)json_object_dotget_number(jo, "arguments.host_port");
	const char *guest_addr_s = json_object_dotget_string(jo, "arguments.guest_addr");
	int guest_port = (int)json_object_dotget_number(jo, "arguments.guest_port");
	if (strcmp(proto_s, "udp") == 0) {
		is_udp = 1;
	} else if (strcmp(proto_s, "tcp") == 0) {
		is_udp = 0;
	}
	if (is_udp == -1) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: bad arguments.proto\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (inet_pton(AF_INET, host_addr_s, &host_addr) != 1) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: bad arguments.host_addr\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (host_port == 0) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: bad arguments.host_port\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (inet_pton(AF_INET, guest_addr_s, &guest_addr) != 1) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: bad arguments.guest_addr\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (guest_port == 0) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: bad arguments.guest_port\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if ((slirprc = slirp_add_hostfwd(slirp, is_udp, host_addr, host_port, guest_addr, guest_port)) < 0) {
		const char *err = "{\"error\":{\"desc\":\"bad request: add_hostfwd: slirp_add_hostfwd failed\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	wrc = write(fd, api_ok, strlen(api_ok));
 finish:
	return wrc;
}

/*
  Handler for remove_hostfwd.
  e.g. {"execute": "remove_hostfwd", "arguments": {"proto": "tcp", "host_addr": "0.0.0.0", "host_port": 8080}}
  This function returns the return value of write(2), not the return value of slirp_remove_hostfwd().
 */
static int api_handle_req_remove_hostfwd(Slirp * slirp, int fd, struct api_ctx *ctx, JSON_Object *jo)
{
	int wrc = 0, slirprc = 0;
	int is_udp = -1;
	const char *proto_s = json_object_dotget_string(jo, "arguments.proto");
	struct in_addr host_addr;
	const char *host_addr_s = json_object_dotget_string(jo, "arguments.host_addr");
	int host_port = (int)json_object_dotget_number(jo, "arguments.host_port");
	if (strcmp(proto_s, "udp") == 0) {
		is_udp = 1;
	} else if (strcmp(proto_s, "tcp") == 0) {
		is_udp = 0;
	}
	if (is_udp == -1) {
		const char *err = "{\"error\":{\"desc\":\"bad request: remove_hostfwd: bad arguments.proto\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (inet_pton(AF_INET, host_addr_s, &host_addr) != 1) {
		const char *err = "{\"error\":{\"desc\":\"bad request: remove_hostfwd: bad arguments.host_addr\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if (host_port == 0) {
		const char *err = "{\"error\":{\"desc\":\"bad request: remove_hostfwd: bad arguments.host_port\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if ((slirprc = slirp_remove_hostfwd(slirp, is_udp, host_addr, host_port)) < 0) {
		const char *err = "{\"error\":{\"desc\":\"bad request: remove_hostfwd: slirp_remove_hostfwd failed\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	wrc = write(fd, api_ok, strlen(api_ok));
 finish:
	return wrc;
}

static int api_handle_req(Slirp * slirp, int fd, struct api_ctx *ctx)
{
	JSON_Value *jv = NULL;
	JSON_Object *jo = NULL;
	const char *execute = NULL;
	int wrc = 0;
	if ((jv = json_parse_string((const char *)ctx->buf)) == NULL) {
		const char *err = "{\"error\":{\"desc\":\"bad request: cannot parse JSON\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if ((jo = json_object(jv)) == NULL) {
		const char *err = "{\"error\":{\"desc\":\"bad request: json_object() failed\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	/* TODO: json_validate */
	if ((execute = json_object_get_string(jo, "execute")) == NULL) {
		const char *err = "{\"error\":{\"desc\":\"bad request: no execute found\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
	if ((strcmp(execute, "add_hostfwd")) == 0) {
		wrc = api_handle_req_add_hostfwd(slirp, fd, ctx, jo);
	} else if ((strcmp(execute, "remove_hostfwd")) == 0) {
		wrc = api_handle_req_remove_hostfwd(slirp, fd, ctx, jo);
	} else {
		const char *err = "{\"error\":{\"desc\":\"bad request: unknown execute\"}}";
		wrc = write(fd, err, strlen(err));
		goto finish;
	}
 finish:
	if (jv != NULL) {
		json_value_free(jv);
	}
	return wrc;
}

/*
  API handler.
  This function returns the return value of either read(2) or write(2).
 */
static int api_handler(Slirp * slirp, int listenfd, struct api_ctx *ctx)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(struct sockaddr_un);
	int fd;
	int rc = 0, wrc = 0;
	ssize_t len;
	memset(&addr, 0, sizeof(addr));
	if ((fd = accept(listenfd, (struct sockaddr *)&addr, &addrlen)) < 0) {
		perror("api_handler: accept");
		return -1;
	}
	if ((len = read(fd, ctx->buf, ctx->buflen)) < 0) {
		perror("api_handler: read");
		rc = len;
		goto finish;
	}
	if (len == ctx->buflen) {
		const char *err = "{\"error\":{\"desc\":\"bad request: too large message\"}}";
		fprintf(stderr, "api_handler: too large message (>= %ld bytes)\n", len);
		wrc = write(fd, err, strlen(err));
		rc = -1;
		goto finish;
	}
	ctx->buf[len] = 0;
	fprintf(stderr, "api_handler: got request: %s\n", ctx->buf);
	wrc = api_handle_req(slirp, fd, ctx);
 finish:
	shutdown(fd, SHUT_RDWR);
	if (rc == 0 && wrc != 0) {
		rc = wrc;
	}
	return rc;
}

#define ETH_BUF_SIZE (65536)

int do_slirp(int tapfd, int exitfd, unsigned int mtu, const char *api_socket, bool ip6_enabled)
{
	int ret = -1;
	Slirp *slirp = NULL;
	uint8_t *buf = NULL;
	struct libslirp_data opaque = {.tapfd = tapfd };
	int apifd = -1;
	struct api_ctx *apictx = NULL;
	GArray pollfds = { 0 };
	int pollfds_exitfd_idx = -1;
	int pollfds_apifd_idx = -1;
	size_t n_fds = 1;
	struct pollfd tap_pollfd = { tapfd, POLLIN | POLLHUP, 0 };
	struct pollfd exit_pollfd = { exitfd, POLLHUP, 0 };
	struct pollfd api_pollfd = { -1, POLLIN | POLLHUP, 0 };

	slirp = create_slirp((void *)&opaque, mtu, ip6_enabled);
	if (slirp == NULL) {
		fprintf(stderr, "create_slirp failed\n");
		goto err;
	}
	buf = malloc(ETH_BUF_SIZE);
	if (buf == NULL) {
		goto err;
	}
	g_array_append_val(&pollfds, tap_pollfd);
	if (exitfd >= 0) {
		n_fds++;
		g_array_append_val(&pollfds, exit_pollfd);
		pollfds_exitfd_idx = n_fds - 1;
	}
	if (api_socket != NULL) {
		if ((apifd = api_bindlisten(api_socket)) < 0) {
			goto err;
		}
		if ((apictx = api_ctx_alloc()) == NULL) {
			fprintf(stderr, "api_ctx_alloc failed\n");
			goto err;
		}
		api_pollfd.fd = apifd;
		n_fds++;
		g_array_append_val(&pollfds, api_pollfd);
		pollfds_apifd_idx = n_fds - 1;
	}
	signal(SIGPIPE, SIG_IGN);
	while (1) {
		int pollout;
		uint32_t timeout = -1;
		pollfds.len = n_fds;
		slirp_pollfds_fill(&pollfds, &timeout);
		update_ra_timeout(&timeout);
		do
			pollout = poll(pollfds.pfd, pollfds.len, timeout);
		while (pollout < 0 && errno == EINTR);
		if (pollout < 0) {
			goto err;
		}

		if (pollfds.pfd[0].revents) {
			ssize_t rc = read(tapfd, buf, ETH_BUF_SIZE);
			if (rc < 0) {
				perror("do_slirp: read");
				goto after_slirp_input;
			}
			slirp_input(slirp, buf, (int)rc);
 after_slirp_input:
			pollout = -1;
		}

		/* The exitfd is closed.  */
		if (pollfds_exitfd_idx >= 0 && pollfds.pfd[pollfds_exitfd_idx].revents) {
			fprintf(stderr, "exitfd event\n");
			goto success;
		}

		if (pollfds_apifd_idx >= 0 && pollfds.pfd[pollfds_apifd_idx].revents) {
			int rc;
			fprintf(stderr, "apifd event\n");
			if ((rc = api_handler(slirp, apifd, apictx)) < 0) {
				fprintf(stderr, "api_handler: rc=%d\n", rc);
			}
		}

		slirp_pollfds_poll(&pollfds, (pollout <= 0));
		check_ra_timeout();
	}
 success:
	ret = 0;
 err:
	fprintf(stderr, "do_slirp is exiting\n");
	if (buf != NULL) {
		free(buf);
	}
	if (apictx != NULL) {
		api_ctx_free(apictx);
	}
	return ret;
}
