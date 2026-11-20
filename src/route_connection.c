/*
Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). 
You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. 
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

/*
 * pgbouncer-rr extension: client connection routing - choose target database pool based on rules
 * applied to client query.
 */

#include <Python.h>
#include "bouncer.h"
#include <usual/pgutil.h>

/*
 * packet_query: point *stmt (Parse only) and *query at the strings in a
 * complete Query or Parse packet. The strings live in pkt's buffer, which the
 * caller must not change while using them. Returns false if the packet is
 * malformed.
 *	PqMsg_Query | int32 len | str query
 *	PqMsg_Parse | int32 len | str stmt | str query | int16 numparams | int32 paramoid...
 */
bool packet_query(PktHdr *pkt, const char **stmt, const char **query, struct MBuf *rest)
{
	struct MBuf body;

	Assert(!incomplete_pkt(pkt));
	if (pkt->len < NEW_HEADER_LEN)
		return false;
	/* pkt->data can run past this packet in the iobuf, so bound it to pkt->len */
	mbuf_init_fixed_reader(&body, mbuf_data(&pkt->data), pkt->len);
	body.read_pos = NEW_HEADER_LEN;
	*stmt = "";
	if (pkt->type == PqMsg_Parse && !mbuf_get_string(&body, stmt))
		return false;
	if (!mbuf_get_string(&body, query))
		return false;
	if (rest)
		*rest = body;
	return true;
}

/* route_client_connection:
 *  - applied to complete packets of type PqMsg_Query (Query) and PqMsg_Parse (Prepare) only
 *  - apply routing rules to the query string and determine the target database
 *  - move the client to that database's pool
 * Returns false if the client was disconnected.
 */
bool route_client_connection(PgSocket *client, int in_transaction, PktHdr *pkt) {
	const char *stmt_str;
	const char *query_str;
	char *dbname;
	PgDatabase *db;
	PgPool *pool;
	PgCredentials *creds;

	if (!is_routing_enabled())
		return true;

	if (!packet_query(pkt, &stmt_str, &query_str, NULL)) {
		disconnect_client(client, true, "malformed %c packet", pkt->type);
		return false;
	}

	slog_debug(client, "route_client_connection: Username => %s", client->login_user_credentials->name);
	slog_debug(client, "route_client_connection: Query => %s", query_str);

	dbname = pycall(client, client->login_user_credentials->name, (char *) query_str, in_transaction, cf_routing_rules_py_module_file,
			"routing_rules");
	if (dbname == NULL) {
		slog_debug(client, "routing_rules returned 'None' - existing connection preserved");
		return true;
	}

	db = find_database(dbname);
	if (db == NULL) {
		/*
		 * Fail closed: staying on the current pool would run this query
		 * against whichever database the connection last used.
		 */
		slog_error(client, "nonexistent database key <%s> returned by routing_rules", dbname);
		disconnect_client(client, true, "unknown database key <%s>", dbname);
		free(dbname);
		return false;
	}
	/*
	 * Use the target database's user=/password= when it has one, as pgbouncer
	 * does at login (see switchover_set_pool). Using the client's credentials
	 * would log in to every backend with the auth_file password and ignore a
	 * per-database password.
	 */
	creds = db->forced_user_credentials ? db->forced_user_credentials : client->login_user_credentials;
	pool = get_pool(db, creds);
	if (client->pool != pool) {
		if (client->link != NULL) {
			/* release existing server connection back to pool */
			slog_debug(client, "releasing existing server connection");
			release_server(client->link);
			client->link = NULL;
		}
		/* assign client to new pool */
		slog_debug(client,
				"assigning client to connection pool for database <%s>",
				dbname);

                /* Move the client over to the other pool for correct pool stats - needed for pool size maint */
                statlist_remove(&client->pool->active_client_list, &client->head);
                statlist_append(&pool->active_client_list, &client->head);

		client->pool = pool;
	} else {
		slog_debug(client, "already connected to pool <%s>", dbname);
	}
	free(dbname);
	return true;
}


bool is_routing_enabled(void) {
	return strcmp(cf_routing_rules_py_module_file, "not_enabled") != 0;
}
