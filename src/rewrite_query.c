/*
Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). 
You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. 
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

/*
 * pgbouncer-rr extension: modify client query before sending to server, using configured python function
 */

#include <Python.h>
#include "bouncer.h"
#include <usual/pgutil.h>

/* private function prototypes */
void printHex(void *buffer, const unsigned int n);
char *strip_newlines(const char *s);
char *tag_rewritten(const char *query);
bool is_rewritten(const char *query);
static bool replace_query(PktHdr *pkt, const char *stmt_str, const char *query_str, struct MBuf *rest);

/* rewrite_query:
 * applied to complete packets of type PqMsg_Query (Query) and PqMsg_Parse (Prepare) only
 */
RewriteResult rewrite_query(PgSocket *client, int in_transaction, PktHdr *pkt) {
	const char *stmt_str, *query_str;
	struct MBuf rest;
	char *loggable_query_str, *tmp_new_query_str, *new_query_str;

	if (!is_rewrite_enabled(client))
		return REWRITE_DONE;

	if (!packet_query(pkt, &stmt_str, &query_str, &rest)) {
		disconnect_client(client, true, "malformed %c packet", pkt->type);
		return REWRITE_FAILED;
	}

	/* don't process same query again */
	if (is_rewritten(query_str))
		return REWRITE_DONE;

	if (unlikely(cf_verbose > 0)) {
		loggable_query_str = strip_newlines(query_str);
		slog_debug(client, "rewrite_query: Username => %s", client->login_user_credentials->name);
		slog_debug(client, "rewrite_query: Orig Query=> %s", loggable_query_str);
		free(loggable_query_str);
	}

	/* call python function to rewrite the query */
	tmp_new_query_str = pycall(client, client->login_user_credentials->name, (char *) query_str, in_transaction,
			cf_rewrite_query_py_module_file, "rewrite_query");
	if (tmp_new_query_str == NULL || strcmp(tmp_new_query_str, query_str) == 0) {
		slog_debug(client, "query unchanged");
		free(tmp_new_query_str);
		return REWRITE_DONE;
	}

	if (client->packet_cb_state.flag != CB_HANDLE_COMPLETE_PACKET) {
		/*
		 * The packet is in the client's iobuf, which is shared with any
		 * pipelined packets after it and can't grow. Have sbuf hand it to
		 * us again in the client's own packet buffer, where we can resize
		 * it; handle_client_work runs again with that copy.
		 */
		free(tmp_new_query_str);
		client->packet_cb_state.flag = CB_WANT_COMPLETE_PACKET;
		sbuf_prepare_fetch(&client->sbuf, pkt->len);
		return REWRITE_REFETCH;
	}
	Assert(pkt == &client->packet_cb_state.pkt);

	new_query_str = tag_rewritten(tmp_new_query_str);
	free(tmp_new_query_str);
	if (unlikely(cf_verbose > 0)) {
		loggable_query_str = strip_newlines(new_query_str);
		slog_debug(client, "rewrite_query: New => %s", loggable_query_str);
		free(loggable_query_str);
	}

	if (!replace_query(pkt, stmt_str, new_query_str, &rest)) {
		free(new_query_str);
		disconnect_client(client, true, "out of memory");
		return REWRITE_FAILED;
	}
	free(new_query_str);
	return REWRITE_DONE;
}

/*
 * Rebuild pkt with query_str in place of its query. stmt_str and rest (the
 * bytes after the query) may point into pkt's current buffer.
 */
static bool replace_query(PktHdr *pkt, const char *stmt_str, const char *query_str, struct MBuf *rest)
{
	struct MBuf buf;
	size_t stmt_len = pkt->type == PqMsg_Parse ? strlen(stmt_str) + 1 : 0;
	size_t query_len = strlen(query_str) + 1;
	unsigned rest_len = mbuf_avail_for_read(rest);
	size_t wire_len = 4 + stmt_len + query_len + rest_len;	/* excludes the type byte */
	uint8_t hdr[NEW_HEADER_LEN];

	if (wire_len > INT32_MAX)
		return false;
	hdr[0] = pkt->type;
	hdr[1] = (wire_len >> 24) & 255;
	hdr[2] = (wire_len >> 16) & 255;
	hdr[3] = (wire_len >> 8) & 255;
	hdr[4] = wire_len & 255;

	mbuf_init_dynamic(&buf);
	if (!mbuf_make_room(&buf, wire_len + 1)
	    || !mbuf_write(&buf, hdr, sizeof(hdr))
	    || !mbuf_write(&buf, stmt_str, stmt_len)
	    || !mbuf_write(&buf, query_str, query_len)
	    || !mbuf_write(&buf, (const uint8_t *) mbuf_data(rest) + rest->read_pos, rest_len)) {
		mbuf_free(&buf);
		return false;
	}
	mbuf_free(&pkt->data);
	pkt->data = buf;
	pkt->len = wire_len + 1;
	pkt_rewind_v3(pkt);
	return true;
}

/* rewrite enabled? */
bool is_rewrite_enabled(PgSocket *client) {
	if (strcmp(cf_rewrite_query_py_module_file, "not_enabled") == 0) {
		slog_debug(client, "Query rewrite not enabled in config (rewrite_query_py_module_file)");
		return false;
	}
	return true;
}

/* copy query string with no newlines, so that it will print correctly in slog_ functions
 */
char *strip_newlines(const char *s) {
	char *n;
	char *p1;
	n = strdup(s);
	if (n == NULL) {
		fatal_perror("strdup");
	}
	for (p1 = n; *p1; p1++) {
		if (*p1 == '\n') {
			*p1 = ' ';
		}
	}
	return n;
}

#define rewritten_template "rewritten_pid='%05d'*/"

/* query tagging to prevent multiple rewrite */
char *tag_rewritten(const char *query) {
	char tag[64];
	char *taggedQuery;
	size_t len = strlen(query);
	size_t keep = len;

	/* if the query ends in a block comment, add the tag to it as another key */
	if (len >= 2 && query[len - 2] == '*' && query[len - 1] == '/') {
		keep = len - 2;
		snprintf(tag, sizeof(tag), "," rewritten_template, getpid());
	} else {
		snprintf(tag, sizeof(tag), "/*" rewritten_template, getpid());
	}
	taggedQuery = malloc(keep + strlen(tag) + 1);
	if (taggedQuery == NULL) {
		fatal_perror("malloc");
	}
	memcpy(taggedQuery, query, keep);
	strcpy(taggedQuery + keep, tag);
	return taggedQuery;
}

bool is_rewritten(const char *query) {
	char tag[64];
	size_t len = strlen(query), tag_len;

	snprintf(tag, sizeof(tag), rewritten_template, getpid());
	tag_len = strlen(tag);
	return len >= tag_len && strcmp(query + len - tag_len, tag) == 0;
}

/* Packet dump for debugging */
void printHex(void *buffer, const unsigned int n) {
	char* data = (char*) buffer;
	unsigned int i = 0;
	char line[17] = { };
	printf("%.8lX | ", (uintptr_t) data);
	while (i < n) {
		line[i % 16] = *(data + i);
		if ((line[i % 16] < 32) || (line[i % 16] > 126)) {
			line[i % 16] = '.';
		}
		printf("%.2X", (unsigned char) *(data + i));
		i++;
		if (i % 4 == 0) {
			if (i % 16 == 0) {
				if (i < n - 1)
					printf(" | %s\n%.8lX | ", (char *) &line,
							(uintptr_t) data + i);
			} else {
				printf(" ");
			}
		}
	}
	while (i % 16 > 0) {
		(i % 4 == 0) ? printf("   ") : printf("  ");
		line[i % 16] = ' ';
		i++;
	}
	printf(" | %s\n", (char *) &line);
}
