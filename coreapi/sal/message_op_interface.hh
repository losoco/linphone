#ifndef _LINPHONE_SAL_MESSAGE_OP_INTERFACE
#define _LINPHONE_SAL_MESSAGE_OP_INTERFACE

class MessageOpInterface {
public:
	virtual int send_message(const char *from, const char *to, const char *msg) {return send_message(from,to,"text/plain",msg, nullptr);}
	virtual int send_message(const char *from, const char *to, const char* content_type, const char *msg, const char *peer_uri) = 0;

protected:
	void prepare_message_request(belle_sip_request_t *req, const char* content_type, const char *msg, const char *peer_uri);
};

#endif // _LINPHONE_SAL_MESSAGE_OP_INTERFACE
