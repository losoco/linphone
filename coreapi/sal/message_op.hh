#ifndef _LINPHONE_SAL_MASSAGE_OP_HH
#define _LINPHONE_SAL_MASSAGE_OP_HH

#include "sal.hh"

class MessageOp: public SalOp {
public:
	int send(const char *from, const char *to, const char *msg) {return send(from,to,"text/plain",msg, NULL);}
	int send(const char *from, const char *to, const char* content_type, const char *msg, const char *peer_uri);
	int reply(SalReason reason);

private:
	void fill_cbs();
	void process_error();
	void process_incoming_message(const belle_sip_request_event_t *event);
	void add_message_accept(belle_sip_message_t *msg);
	
	static bool_t is_external_body(belle_sip_header_content_type_t* content_type);
	
	static void process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event);
	static void process_response_event_cb(void *op_base, const belle_sip_response_event_t *event);
	static void process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event);
	static void process_request_event_cb(void *op_base, const belle_sip_request_event_t *event);
};

#endif // _LINPHONE_SAL_MASSAGE_OP_HH
