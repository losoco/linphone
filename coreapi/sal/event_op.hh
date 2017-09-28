#ifndef _LINPHONE_SAL_EVENT_OP_HH
#define _LINPHONE_SAL_EVENT_OP_HH

#include "sal.hh"

class SalEventOp: public SalOp {
public:
		SalEventOp(Sal *sal): SalOp(sal) {}
};

class SalSubscribeOp: public SalEventOp {
public:
		SalSubscribeOp(Sal *sal): SalEventOp(sal) {}
	
	int subscribe(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler);
	int unsubscribe() {return SalOp::unsubscribe();}
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
	static void _release_cb(SalOp *op_base);
	static void subscribe_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry);
};

class SalPublishOp: public SalEventOp {
public:
    	SalPublishOp(Sal *sal): SalEventOp(sal) {}
    
	int publish(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler);
	int unpublish();

private:
	virtual void fill_cbs() override;
	
	static void publish_response_event_cb(void *userctx, const belle_sip_response_event_t *event);
	static void publish_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry);
};

#endif
