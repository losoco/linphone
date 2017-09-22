#ifndef _LINPHONE_SAL_PUBLISH_OP
#define _LINPHONE_SAL_PUBLISH_OP

#include "sal.hh"

class PublishOp: public SalOp {
public:
	int publish(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler);
	int unpublish();

private:
	virtual void fill_cbs() override;
	
	static void publish_response_event_cb(void *userctx, const belle_sip_response_event_t *event);
	static void publish_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry);
};

#endif
