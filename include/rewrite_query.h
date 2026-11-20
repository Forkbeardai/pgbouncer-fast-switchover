/*
Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). 
You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. 
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

/*
 * pgbouncer-rr extension: client connection rewriting
 */

typedef enum {
	REWRITE_DONE,		/* carry on with pkt, rewritten or not */
	REWRITE_REFETCH,	/* pkt is being re-read for rewriting; return true */
	REWRITE_FAILED,		/* client was disconnected; return false */
} RewriteResult;

RewriteResult rewrite_query(PgSocket *client, int in_transaction, PktHdr *pkt);
bool is_rewrite_enabled(PgSocket *client);


void printHex(void *buffer, const unsigned int n) ;
