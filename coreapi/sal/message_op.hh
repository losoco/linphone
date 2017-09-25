#ifndef _LINPHONE_SAL_MASSAGE_OP_HH
#define _LINPHONE_SAL_MASSAGE_OP_HH

#include "sal.hh"
#include "message_op_interface.hh"

class MessageOp: public SalOp, public MessageOpInterface {
public:
	MessageOp(Sal *sal): SalOp(sal) {}
	
	virtual int send_message(const char *from, const char *to, const char* content_type, const char *msg, const char *peer_uri) override;
	virtual int reply(SalReason reason) override {return SalOp::reply_message(reason);}

private:
	virtual void fill_cbs() override;
	void process_error();
	
	static void process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event);
	static void process_response_event_cb(void *op_base, const belle_sip_response_event_t *event);
	static void process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event);
	static void process_request_event_cb(void *op_base, const belle_sip_request_event_t *event);
};

#endif // _LINPHONE_SAL_MASSAGE_OP_HH
