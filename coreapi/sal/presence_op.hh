#ifndef _LINPHONE_SAL_PRESENCE_OP
#define _LINPHONE_SAL_PRESENCE_OP

#include "sal.hh"

class PresenceOp: public SalOp {
public:
	PresenceOp(Sal *sal): SalOp(sal) {}
	
	int subscribe(const char *from, const char *to, int expires);
    int unsubscribe() {return SalOp::unsubscribe();}
	int notify_presence(SalPresenceModel *presence);
	int notify_presence_close();

private:
	virtual void fill_cbs() override;
	void handle_notify(belle_sip_request_t *req, belle_sip_dialog_t *dialog);
	SalPresenceModel * process_presence_notification(belle_sip_request_t *req);
	int check_dialog_state();
	belle_sip_request_t *create_presence_notify();
	void add_presence_info(belle_sip_message_t *notify, SalPresenceModel *presence);
	
	static SalSubscribeStatus belle_sip_message_get_subscription_state(const belle_sip_message_t *msg);
	
	static void presence_process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event);
	static void presence_response_event_cb(void *op_base, const belle_sip_response_event_t *event);
	static void presence_refresher_listener_cb(belle_sip_refresher_t* refresher, void* user_pointer, unsigned int status_code, const char* reason_phrase, int will_retry);
	static void presence_process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event);
	static void presence_process_transaction_terminated_cb(void *user_ctx, const belle_sip_transaction_terminated_event_t *event);
	static void presence_process_request_event_cb(void *op_base, const belle_sip_request_event_t *event);
	static void presence_process_dialog_terminated_cb(void *ctx, const belle_sip_dialog_terminated_event_t *event);
	static void _release_cb(SalOp *op_base);
};

#endif // _LINPHONE_SAL_PRESENCE_OP
