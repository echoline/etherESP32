#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "NinePea.h"
#include "wifi.h"
#include "esp_pthread.h"

static Fcall ofcall;
static char errstr[64];
static char Snone[] = "esp32";
static char Sroot[] = "/";
static char Sether[] = "etherESP32";
static char Saddr[] = "addr";
static char Sclone[] = "clone";
static char Sifstats[] = "ifstats";
static char Sstats[] = "stats";
static char Sctl[] = "ctl";
static char Sdata[] = "data";
static char Stype[] = "type";
static char Sconn[13];

typedef struct {
	int type;
} Conn;

static int nconns = 0;
static Conn *conns = NULL;

/* paths */

enum {
	Qroot = 0,
	Qether,
	Qaddr,
	Qclone,
	Qifstats,
	Qstats,
	Qctl,
	Qdata,
	Qtype,
	QNUM,
};

/* 9p handlers */

static Fcall*
fs_attach(Fcall *ifcall) {
	ofcall.qid.type = QTDIR | QTTMP;
	ofcall.qid.version = 0;
	ofcall.qid.path = Qroot;

	fs_fid_add(ifcall->fid, Qroot);

	return &ofcall;
}

static Fcall*
fs_walk(Fcall *ifcall) {
	unsigned long path;
	struct hentry *ent = fs_fid_find(ifcall->fid);
	int i, j, l, conn = -1;

	if (!ent) {
		ofcall.type = RError;
		ofcall.ename = Enofile;

		return &ofcall;
	}

	path = ent->data;

	for (i = 0; i < ifcall->nwname; i++) {
		switch(path) {
		case Qroot:
			if (!strcmp(ifcall->wname[i], ".")) {
				ofcall.wqid[i].type = QTDIR;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qroot;
			}
			else if (!strcmp(ifcall->wname[i], "etherESP32")) {
				ofcall.wqid[i].type = QTDIR;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qether;
			}
			else {
				ofcall.type = RError;
				ofcall.ename = Enofile;
				return &ofcall;
			}
			break;
		case Qether:
			if (!strcmp(ifcall->wname[i], "..")) {
				ofcall.wqid[i].type = QTDIR;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qroot;
			}
			else if (!strcmp(ifcall->wname[i], ".")) {
				ofcall.wqid[i].type = QTDIR;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qether;
			}
			else if (!strcmp(ifcall->wname[i], "addr")) {
				ofcall.wqid[i].type = QTFILE;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qaddr;
			}
			else if (!strcmp(ifcall->wname[i], "clone")) {
				ofcall.wqid[i].type = QTFILE;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qclone;
			}
			else if (!strcmp(ifcall->wname[i], "ifstats")) {
				ofcall.wqid[i].type = QTFILE;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qifstats;
			}
			else if (!strcmp(ifcall->wname[i], "stats")) {
				ofcall.wqid[i].type = QTFILE;
				ofcall.wqid[i].version = 0;
				ofcall.wqid[i].path = path = Qstats;
			}
			else {
				l = strlen(ifcall->wname[i]);
				for (j = 0; j < l; j++) {
					if (!isdigit(ifcall->wname[i][j])) {
						ofcall.type = RError;
						ofcall.ename = Enofile;
						return &ofcall;
					}
				}
				conn = atoi(ifcall->wname[i]);
				if (conn < nconns) {
					ofcall.wqid[i].type = QTDIR;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = QNUM + conn;
				} else {
					ofcall.type = RError;
					ofcall.ename = Enofile;
					return &ofcall;
				}
			}
			break;
		default:
			if (path >= QNUM) {
				conn = path - QNUM;
				if (conn >= nconns) {
					ofcall.type = RError;
					ofcall.ename = Enofile;

					return &ofcall;
				}
				if (!strcmp(ifcall->wname[i], ".")) {
					ofcall.wqid[i].type = QTDIR;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path;
				}
				else if (!strcmp(ifcall->wname[i], "..")) {
					ofcall.wqid[i].type = QTDIR;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qether;
				}
				else if (!strcmp(ifcall->wname[i], "ctl")) {
					ofcall.wqid[i].type = QTFILE;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qctl;
				}
				else if (!strcmp(ifcall->wname[i], "data")) {
					ofcall.wqid[i].type = QTFILE;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qdata;
				}
				else if (!strcmp(ifcall->wname[i], "ifstats")) {
					ofcall.wqid[i].type = QTFILE;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qifstats;
				}
				else if (!strcmp(ifcall->wname[i], "stats")) {
					ofcall.wqid[i].type = QTFILE;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qstats;
				}
				else if (!strcmp(ifcall->wname[i], "type")) {
					ofcall.wqid[i].type = QTFILE;
					ofcall.wqid[i].version = 0;
					ofcall.wqid[i].path = path = Qtype;
				}
				else {
					ofcall.type = RError;
					ofcall.ename = Enofile;

					return &ofcall;
				}
			} else {
				ofcall.type = RError;
				ofcall.ename = Enofile;

				return &ofcall;
			}
			break;
		}
	}

	ofcall.nwqid = i;

	if (fs_fid_find(ifcall->newfid) != NULL) {
		ofcall.type = RError;
		strcpy(errstr, "new fid exists");
		ofcall.ename = errstr;
		return &ofcall;
	}

	ent = fs_fid_add(ifcall->newfid, path);
	ent->conn = conn;

	return &ofcall;
}

static Fcall*
fs_stat(Fcall *ifcall) {
	struct hentry *ent;

	if ((ent = fs_fid_find(ifcall->fid)) == NULL) {
		ofcall.type = RError;
		ofcall.ename = Enofile;

		return &ofcall;
	}

	ofcall.stat.qid.type = QTTMP;
	ofcall.stat.mode = 0444 | DMTMP;
	ofcall.stat.atime = ofcall.stat.mtime = ofcall.stat.length = 0;
	ofcall.stat.uid = Snone;
	ofcall.stat.gid = Snone;
	ofcall.stat.muid = Snone;

	switch (ent->data) {
	case Qroot:
		ofcall.stat.qid.type |= QTDIR;
		ofcall.stat.qid.path = Qroot;
		ofcall.stat.mode |= 0777 | DMDIR;
		ofcall.stat.name = Sroot;
		break;
	case Qether:
		ofcall.stat.qid.type |= QTDIR;
		ofcall.stat.qid.path = Qether;
		ofcall.stat.mode |= 0777 | DMDIR;
		ofcall.stat.name = Sether;
		break;
	case Qaddr:
		ofcall.stat.qid.path = Qaddr;
		ofcall.stat.name = Saddr;
		break;
	case Qclone:
		ofcall.stat.qid.path = Qclone;
		ofcall.stat.mode |= 0222;
		ofcall.stat.name = Sclone;
		break;
	case Qifstats:
		ofcall.stat.qid.path = Qifstats;
		ofcall.stat.name = Sifstats;
		break;
	case Qstats:
		ofcall.stat.qid.path = Qstats;
		ofcall.stat.name = Sstats;
		break;
	case Qctl:
		ofcall.stat.qid.path = Qctl;
		ofcall.stat.mode = 0660;
		ofcall.stat.name = Sctl;
		break;
	case Qdata:
		ofcall.stat.qid.path = Qdata;
		ofcall.stat.mode = 0660;
		ofcall.stat.name = Sdata;
		break;
	case Qtype:
		ofcall.stat.qid.path = Qtype;
		ofcall.stat.name = Stype;
		break;
	}

	if ((ent->data - QNUM) < nconns) {
		ofcall.stat.qid.type |= QTDIR;
		ofcall.stat.qid.path = ent->data;
		ofcall.stat.mode = 0777 | DMDIR;
		snprintf(Sconn, 12, "%lu", ent->data - QNUM);
		ofcall.stat.name = Sconn;
	}

	return &ofcall;
}

static Fcall*
fs_clunk(Fcall *ifcall) {
	fs_fid_del(ifcall->fid);

	return ifcall;
}

static Fcall*
fs_open(Fcall *ifcall) {
	struct hentry *cur = fs_fid_find(ifcall->fid);

	if (cur == NULL) {
		ofcall.type = RError;
		ofcall.ename = Enofile;

		return &ofcall;
	}

	ofcall.qid.type = QTFILE;
	ofcall.qid.path = cur->data;

	if (cur->data == Qroot)
		ofcall.qid.type = QTDIR;
	else if (cur->data == Qether)
		ofcall.qid.type = QTDIR;

	return &ofcall;
}

static Fcall*
fs_read(Fcall *ifcall, unsigned char *out) {
	struct hentry *cur = fs_fid_find(ifcall->fid);
	Stat stat;
	unsigned long id;

	ofcall.count = 0;

	if (cur == NULL) {
		ofcall.type = RError;
		ofcall.ename = Enofile;
	}
	else if (((unsigned long)cur->data) == Qroot) {
		stat.type = 0;
		stat.dev = 0;
		stat.qid.type = QTFILE | QTDIR;
		stat.qid.path = Qether;
		stat.mode = 0777 | DMDIR;
		stat.atime = 0;
		stat.mtime = 0;
		stat.length = 0;
		stat.name = Sether;
		stat.uid = stat.gid = stat.muid = Snone;
		ofcall.count += putstat(out, ofcall.count, &stat);
	}
	else if (((unsigned long)cur->data) == Qether) {
		stat.type = 0;
		stat.dev = 0;
		stat.qid.type = QTFILE;
		stat.atime = 0;
		stat.mtime = 0;
		stat.length = 0;
		stat.uid = stat.gid = stat.muid = Snone;

		for (id = 0; id < nconns; id++) {
			stat.qid.type |= QTDIR;
			stat.qid.path = QNUM + id;
			stat.mode = 0777 | DMDIR;
			snprintf(Sconn, 12, "%lu", id);
			stat.name = Sconn;
			ofcall.count += putstat(out, ofcall.count, &stat);
		}

		stat.qid.type = QTFILE;

		stat.mode = 0444;
		stat.name = Saddr;
		stat.qid.path = Qaddr;
		ofcall.count += putstat(out, ofcall.count, &stat);

		stat.mode = 0666;
		stat.name = Sclone;
		stat.qid.path = Qclone;
		ofcall.count += putstat(out, ofcall.count, &stat);

		stat.mode = 0444;
		stat.name = Sifstats;
		stat.qid.path = Qifstats;
		ofcall.count += putstat(out, ofcall.count, &stat);

		stat.mode = 0444;
		stat.name = Sstats;
		stat.qid.path = Qstats;
		ofcall.count += putstat(out, ofcall.count, &stat);
	}
	else if (((unsigned long)cur->data) == Qaddr) {
		get_mac_address((char*)out);
		ofcall.count = 12;
	}
	else if (((unsigned long)cur->data) == Qclone) {
		cur->conn = nconns;
		ofcall.count = sprintf((char*)out, "%11d ", nconns++);
		conns = realloc(conns, nconns * sizeof(Conn));
	}
	else if (((unsigned long)cur->data) == Qstats) {
		ofcall.count = read_stats((char*)out);
	}
	else if (((unsigned long)cur->data) == Qifstats) {
		ofcall.count = read_ifstats((char*)out);
	}
	else if (((unsigned long)cur->data) == Qdata) {
		ofcall.count = read_data((char*)out);
	}
	else if (((unsigned long)cur->data) >= QNUM) {
		id = (unsigned long)cur->data - QNUM;
		if (id >= nconns) {
			ofcall.type = RError;
			ofcall.ename = Enofile;
		} else {
			stat.type = 0;
			stat.dev = 0;
			stat.qid.type = QTFILE;
			stat.atime = 0;
			stat.mtime = 0;
			stat.length = 0;
			stat.uid = stat.gid = stat.muid = Snone;

			stat.mode = 0660;
			stat.name = Sctl;
			stat.qid.path = Qctl;
			ofcall.count += putstat(out, ofcall.count, &stat);

			stat.mode = 0660;
			stat.name = Sdata;
			stat.qid.path = Qdata;
			ofcall.count += putstat(out, ofcall.count, &stat);

			stat.mode = 0444;
			stat.name = Sifstats;
			stat.qid.path = Qifstats;
			ofcall.count += putstat(out, ofcall.count, &stat);

			stat.mode = 0444;
			stat.name = Sstats;
			stat.qid.path = Qstats;
			ofcall.count += putstat(out, ofcall.count, &stat);

			stat.mode = 0444;
			stat.name = Stype;
			stat.qid.path = Qtype;
			ofcall.count += putstat(out, ofcall.count, &stat);
		}
	}
	else {
		ofcall.type = RError;
		ofcall.ename = Enofile;
	}

	if (ifcall->offset != 0) {
		if (ofcall.count >= ifcall->offset) {
			memmove(out, &out[ifcall->offset], ofcall.count - ifcall->offset);
			ofcall.count -= ifcall->offset;
		}
	}

	if (ofcall.count > ifcall->count)
		ofcall.count = ifcall->count;

	return &ofcall;
}

static Fcall*
fs_create(Fcall *ifcall) {
	ofcall.type = RError;
	ofcall.ename = Eperm;

	return &ofcall;
}

static Fcall*
fs_write(Fcall *ifcall, unsigned char *in) {
	struct hentry *cur = fs_fid_find(ifcall->fid);

	if (cur == NULL) {
		ofcall.type = RError;
		ofcall.ename = Enofile;

		return &ofcall;
	}

	if (((unsigned long)cur->data) == Qclone) {
		if (strncmp((const char*)in, "connect ", 8) == 0) {
			in[ifcall->count] = '\0';
			in[strcspn((const char*)in, "\r\n")] = '\0';

			conns[cur->conn].type = strtoul((const char*)&in[8], 0, 0);

			ofcall.count = ifcall->count;
			return &ofcall;
		}
		if (conns[cur->conn].type == 0x888e) {
			if (strncmp((const char*)in, "essid ", 6) == 0) {
				in[ifcall->count] = '\0';
				in[strcspn((const char*)in, "\r\n")] = '\0';

				set_essid((char*)&in[6]);

				ofcall.count = ifcall->count;
				return &ofcall;
			}
		}
	}

	ofcall.type = RError;
	ofcall.ename = Eperm;

	return &ofcall;
}

static Fcall*
fs_remove(Fcall *ifcall) {
	ofcall.type = RError;
	ofcall.ename = Eperm;

	return &ofcall;
}

static Fcall*
fs_flush(Fcall *ifcall) {
	return ifcall;
}

static Fcall*
fs_wstat(Fcall *ifcall) {
	ofcall.type = RError;
	ofcall.ename = Eperm;

	return &ofcall;
}

static void
sysfatal(int code)
{
	while(true) {
		sleep(1);
	}
}

void
app_main(void)
{
	uint8_t *msg;
	unsigned long msglen = 0;
	unsigned long r = 0;
	unsigned long i;
	unsigned long l;

	Callbacks callbacks;

	esp_pthread_cfg_t cfg = esp_pthread_get_default_config();
	cfg.stack_size = (4 * 1024);
	esp_pthread_set_cfg(&cfg);

	init_wifi();

	fs_fid_init(64);

	msg = malloc(MAX_MSG+1);

	// this is REQUIRED by proc9p (see below)
	callbacks.attach = fs_attach;
	callbacks.flush = fs_flush;
	callbacks.walk = fs_walk;
	callbacks.open = fs_open;
	callbacks.create = fs_create;
	callbacks.read = fs_read;
	callbacks.write = fs_write;
	callbacks.clunk = fs_clunk;
	callbacks.remove = fs_remove;
	callbacks.stat = fs_stat;
	callbacks.wstat = fs_wstat;

	uart_config_t uart_config = {
		.baud_rate = 2000000,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_APB,
	};
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 2048, 0, 0, NULL, 0));
	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));

	for(;;) {
		i = 0;
		do {
			l = uart_read_bytes(UART_NUM_0, &msg[r], 5 - r, 20 / portTICK_RATE_MS);
			r += l;
		} while (r < 5);
		get4(msg, i, msglen);

		// sanity check
		if (msg[i] & 1 || msglen > MAX_MSG || msg[i] < TVersion || msg[i] > TWStat) {
			sysfatal(3);
		}

		do {
			l = uart_read_bytes(UART_NUM_0, &msg[r], msglen - r, 20 / portTICK_RATE_MS);
			r += l;
		} while (r < msglen);

		memset(&ofcall, 0, sizeof(ofcall));

		// proc9p accepts valid 9P msgs of length msglen,
		// processes them using callbacks->various(functions);
		// returns variable out's msglen
		msglen = proc9p(msg, msglen, &callbacks);

		uart_write_bytes(UART_NUM_0, (const char*)msg, msglen);

		r = msglen = 0;
	}
}

