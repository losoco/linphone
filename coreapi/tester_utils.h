/*
tester_utils.h
Copyright (C) 2017  Belledonne Communications SARL

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef _TESTER_UTILS_H_
#define _TESTER_UTILS_H_

#include "account_creator.h"
#include "linphone/core.h"
#include "linphone/tunnel.h"
#include "sal/sal.h"
#include <sqlite3.h> 

typedef struct _Sal Sal;
typedef struct _SalOp SalOp;

#ifdef __cplusplus
extern "C" {
#endif

LINPHONE_PUBLIC Sal *linphone_core_get_sal(const LinphoneCore *lc);
LINPHONE_PUBLIC bool_t linphone_core_rtcp_enabled(const LinphoneCore *lc);
LINPHONE_PUBLIC void linphone_core_get_local_ip(LinphoneCore *lc, int af, const char *dest, char *result);
LINPHONE_PUBLIC void linphone_core_enable_forced_ice_relay(LinphoneCore *lc, bool_t enable);
LINPHONE_PUBLIC void linphone_core_set_zrtp_not_available_simulation(LinphoneCore *lc, bool_t enabled);
LINPHONE_PUBLIC belle_http_provider_t *linphone_core_get_http_provider(const LinphoneCore *lc);

LINPHONE_PUBLIC sqlite3 *linphone_core_get_sqlite_database(const LinphoneCore *lc);
LINPHONE_PUBLIC void linphone_core_set_zrtp_cache_db(LinphoneCore *lc, sqlite3 *cache_db);

LINPHONE_PUBLIC LinphoneCoreCbs *linphone_core_get_first_callbacks(const LinphoneCore *lc);
LINPHONE_PUBLIC void _linphone_core_add_callbacks(LinphoneCore *lc, LinphoneCoreCbs *vtable, bool_t internal);

LINPHONE_PUBLIC bctbx_list_t * linphone_core_read_call_logs_from_config_file(LinphoneCore *lc);
LINPHONE_PUBLIC bctbx_list_t **linphone_core_get_call_logs_attribute(LinphoneCore *lc);
LINPHONE_PUBLIC void linphone_core_delete_call_log(LinphoneCore *lc, LinphoneCallLog *log);

LINPHONE_PUBLIC const MSList *linphone_core_get_call_history(LinphoneCore *lc);
LINPHONE_PUBLIC void linphone_core_delete_call_history(LinphoneCore *lc);
LINPHONE_PUBLIC int linphone_core_get_call_history_size(LinphoneCore *lc);

LINPHONE_PUBLIC void linphone_core_cbs_set_auth_info_requested(LinphoneCoreCbs *cbs, LinphoneCoreAuthInfoRequestedCb cb);

LINPHONE_PUBLIC SalOp *linphone_proxy_config_get_sal_op(const LinphoneProxyConfig *cfg);

LINPHONE_PUBLIC SalOp *linphone_call_get_op_as_sal_op(const LinphoneCall *call);
LINPHONE_PUBLIC MediaStream * linphone_call_get_stream(LinphoneCall *call, LinphoneStreamType type);
LINPHONE_PUBLIC bool_t linphone_call_get_all_muted(const LinphoneCall *call);

LINPHONE_PUBLIC void linphone_call_params_set_no_user_consent(LinphoneCallParams *params, bool_t value);

LINPHONE_PUBLIC bool_t linphone_call_stats_is_updated(const LinphoneCallStats *stats);
LINPHONE_PUBLIC bool_t linphone_call_stats_get_rtcp_received_via_mux(const LinphoneCallStats *stats);
LINPHONE_PUBLIC mblk_t *linphone_call_stats_get_received_rtcp(const LinphoneCallStats *stats);

LINPHONE_PUBLIC bctbx_list_t * linphone_chat_room_get_transient_messages(const LinphoneChatRoom *cr);

LINPHONE_PUBLIC void linphone_friend_invalidate_subscription(LinphoneFriend *lf);
LINPHONE_PUBLIC void linphone_friend_update_subscribes(LinphoneFriend *fr, bool_t only_when_registered);
LINPHONE_PUBLIC MSList *linphone_friend_get_insubs(const LinphoneFriend *fr);
LINPHONE_PUBLIC int linphone_friend_list_get_expected_notification_version(const LinphoneFriendList *list);

LINPHONE_PUBLIC int sal_create_uuid(Sal *ctx, char *uuid, size_t len);
LINPHONE_PUBLIC char *sal_get_random_token(int size);
LINPHONE_PUBLIC void sal_set_uuid(Sal *ctx, const char *uuid);

LINPHONE_PUBLIC void sal_default_set_sdp_handling(Sal* h, SalOpSDPHandling handling_method) ;
LINPHONE_PUBLIC	void sal_set_send_error(Sal *sal,int value);
LINPHONE_PUBLIC	void sal_set_recv_error(Sal *sal,int value);
LINPHONE_PUBLIC int sal_enable_pending_trans_checking(Sal *sal, bool_t value);
LINPHONE_PUBLIC	void sal_enable_unconditional_answer(Sal *sal,int value);
LINPHONE_PUBLIC	void sal_set_dns_timeout(Sal* sal,int timeout);
LINPHONE_PUBLIC void *sal_get_stack_impl(Sal *sal);

LINPHONE_PUBLIC const SalErrorInfo *sal_op_get_error_info(const SalOp *op);
LINPHONE_PUBLIC bool_t sal_call_dialog_request_pending(const SalOp *op);
LINPHONE_PUBLIC void sal_call_set_sdp_handling(SalOp *h, SalOpSDPHandling handling);

#ifdef __cplusplus
}
#endif



#endif // _TESTER_UTILS_H_
