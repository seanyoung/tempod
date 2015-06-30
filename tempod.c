
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <math.h>
#include <time.h>
#include <syslog.h>

/* lib */
#include <evhttp.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>


#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define SERVER_NAME	"tempod/0.1-git" GIT_COMMIT

static double temperature = INFINITY;
static unsigned pressure, humidity;
static int hci_socket;
static struct event *g_evtime;
static struct event_base *g_base;
static char *g_statsfile = "/var/log/tempod/measurements.csv";
static bool foundtempod = true;
static time_t g_lastlog;

static void ble_read(evutil_socket_t fd, short event, void *arg);

static void logit()
{
	// log it
	time_t now = time(NULL);
	char buf[100];
	size_t size;

	size = snprintf(buf, sizeof(buf), "%ld,%.1f,%d,%d\n", now, temperature,humidity,pressure);

	int fd = TEMP_FAILURE_RETRY(open(g_statsfile, O_APPEND|O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
	if (fd == -1) {
		syslog(LOG_WARNING, "failed to write %s: %m", g_statsfile);
		return;
	}
	
	size_t off = 0;
	while (size) {
		ssize_t ret = TEMP_FAILURE_RETRY(write(fd, buf + off, size));
		if (ret == -1) {
			syslog(LOG_WARNING, "failed to write %s: %m", g_statsfile);
			TEMP_FAILURE_RETRY(close(fd));
			return;
		}
		off += ret;
		size -= ret;
	}

	TEMP_FAILURE_RETRY(close(fd));

	g_lastlog = now;
}

static int ble_setup()
{
	int hci_device_id = hci_get_route(NULL);

	if (hci_device_id < 0)
		hci_device_id = 0;

	hci_socket = hci_open_dev(hci_device_id);
	if (hci_socket == -1) {
		printf("error: unable to open hci device\n");
		return -1;
	}

	ioctl(hci_socket, HCIDEVDOWN, hci_device_id);
	ioctl(hci_socket, HCIDEVRESET, hci_device_id);

	/* FIXME: should we set non-blocking mode on hci socket? */
	struct hci_filter new_filter;

	hci_filter_clear(&new_filter);
	hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
	hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);
	setsockopt(hci_socket, SOL_HCI, HCI_FILTER, &new_filter, sizeof(new_filter));

	if (ioctl(hci_socket, HCIDEVUP, hci_device_id)) {
		printf("error: hci device up: %m\n");
		close(hci_socket);
		return -1;
	}

	if (hci_le_set_scan_parameters(hci_socket, 0x01, htobs(0x0010), htobs(0x0010), 0x00, 0, 1000) < 0) {
		printf("error: Cannot set le scan parameters: %m");
		close(hci_socket);
		return -1;
	}

	struct event *event = event_new(g_base, hci_socket,
				EV_READ | EV_PERSIST, ble_read, NULL);

	event_add(event, NULL);

	return 0;
}

static void ble_start_scan(evutil_socket_t fd, short event, void *arg)
{
	if (!foundtempod) 
		syslog(LOG_WARNING, "warning: no response from tempod device");

	foundtempod = false;
	hci_le_set_scan_enable(hci_socket, 0x00, 1, 1000);
	hci_le_set_scan_enable(hci_socket, 0x01, 1, 1000);

	evtimer_add(g_evtime, &((struct timeval) { 60, 0 }));
}

static void ble_read(evutil_socket_t fd, short event, void *arg)
{
	unsigned char hciEventBuf[HCI_MAX_EVENT_SIZE];
	int hciEventLen;
	evt_le_meta_event *leMetaEvent;
	le_advertising_info *leAdvertisingInfo;
	
	hciEventLen = TEMP_FAILURE_RETRY(read(hci_socket, hciEventBuf, sizeof(hciEventBuf)));
	if (hciEventLen == -1) {
		syslog(LOG_ERR, "failed to read hci device: %m");
		exit(EXIT_FAILURE);
	}
	leMetaEvent = (evt_le_meta_event *)(hciEventBuf + (1 + HCI_EVENT_HDR_SIZE));
	hciEventLen -= (1 + HCI_EVENT_HDR_SIZE);	

	if (leMetaEvent->subevent != 0x02)
		return;

	leAdvertisingInfo = (le_advertising_info *)(leMetaEvent->data + 1);

	if (leAdvertisingInfo->length < 16 || 
				leAdvertisingInfo->data[0] != 0x0f ||
				leAdvertisingInfo->data[1] != 0xff)
		return;

	temperature = (leAdvertisingInfo->data[5] +
		leAdvertisingInfo->data[6] * 256) / 10.0;
	humidity =  leAdvertisingInfo->data[11];
	pressure =  leAdvertisingInfo->data[12] +
			leAdvertisingInfo->data[13] * 256;

	// stop scanning
	hci_le_set_scan_enable(hci_socket, 0x00, 1, 1000);

	foundtempod = true;
	logit();
}

static void process_req(struct evhttp_request *req, void *arg)
{
	if (!isfinite(temperature)) {
		evhttp_send_error(req, HTTP_SERVUNAVAIL, "Not ready");
		return;
	}
	
	time_t now = time(NULL);

	if (g_lastlog < now - 15*60) {
		evhttp_send_error(req, HTTP_SERVUNAVAIL, "Stale");
		return;
	}

	struct evbuffer *buf = evbuffer_new();

	evbuffer_add_printf(buf, "{ \"temperature\": %.1f, "
				"\"humidity\": %u, "
				"\"pressure\": %u }\n",
			temperature, humidity, pressure);

	evhttp_add_header(req->output_headers, "Server", SERVER_NAME);
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evhttp_add_header(req->output_headers, "Connection", "close");
	evhttp_send_reply(req, HTTP_OK, "OK", buf);
	evbuffer_free(buf);
}

int create_http(int port)
{
	struct evhttp *httpd = evhttp_new(g_base);
	if (httpd == NULL)
		return ENOMEM;

	if (evhttp_bind_socket(httpd, "::", port)) {
		evhttp_free(httpd);
		return errno;
	}

	evhttp_set_cb(httpd, "/", process_req, NULL);

	return 0;
}

int main(int argc, char *argv[])
{
	int rc, port = 80;
	bool daemonize = true;

	opterr = 0;

	while ((rc = getopt(argc, argv, "hdp:")) != -1) {
		switch (rc) {
		case 'd':
			daemonize = false;
			break;
		case 'p':
			port = atoi(optarg);
			if (port <= 0 || port >= 65536) {
				fprintf(stderr, "error: %s is not a valid port",
								optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			printf("Usage: %s [-d] [-p port] [-h]\n", argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			fprintf(stderr, "error: invalid argument -%c\n", optopt);
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "error: invalid argument '%s'\n", argv[optind]);
		exit(EXIT_FAILURE);
	}
	g_base = event_init();

	if (ble_setup())
		exit(EXIT_FAILURE);

	rc = create_http(port);
	if (rc) {
		printf("error: failed to create http server: %s\n", strerror(rc));
		exit(EXIT_FAILURE);
	}

	g_evtime = evtimer_new(g_base, ble_start_scan, NULL);
	ble_start_scan(0, 0, NULL);

	if (daemonize && daemon(0, 0)) {
		printf("error: failed to fork: %m\n");
		exit(EXIT_FAILURE);
	}

	openlog("tempod", LOG_ODELAY | LOG_PID, LOG_USER);
	event_base_dispatch(g_base);
	closelog();

	return 0;
}


