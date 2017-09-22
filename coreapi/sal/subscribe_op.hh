#ifndef _LINPHONE_SAL_SUBSCRIBE_OP
#define _LINPHONE_SAL_SUBSCRIBE_OP

#include "sal.hh"

class SubscribeOp: public SalOp {
public:
	SubscribeOp(Sal *sal): SalOp(sal) {}
	
	int subscribe(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler);
	int unsubscribe();
	int accept();
	int decline(SalReason reason);
	int notify_pending_state();
	int notify(const SalBodyHandler *body_handler);
	int close_notify();

private:
	virtual void fill_cbs() override;
	void handle_notify(belle_sip_request_t *req, const char *eventname, SalBodyHandler* body_handler);
	
	static void subscribe_process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event);
	static void subscribe_response_event_cb(void *op_base, const belle_sip_response_event_t *event);
	static void subscribe_process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event);
	static void subscribe_process_transaction_terminated_cb(void *user_ctx, const belle_sip_transaction_terminated_event_t *event) {}
	static void subscribe_process_request_event_cb(void *op_base, const belle_sip_request_event_t *event);
	static void subscribe_process_dialog_terminated_cb(void *ctx, const belle_sip_dialog_terminated_event_t *event);
	static void release_cb(void *op_base);
	static void subscribe_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry);
};

#endif // _LINPHONE_SAL_SUBSCRIBE_OP
