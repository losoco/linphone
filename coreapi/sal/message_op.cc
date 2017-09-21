#include "message_op.hh"

using namespace std;

void MessageOp::process_error() {
	if (this->dir == Dir::Outgoing) {
		this->root->callbacks.message_delivery_update(this, SalMessageDeliveryFailed);
	} else {
		ms_warning("unexpected io error for incoming message on op [%p]", this);
	}
	this->state=State::Terminated;
}

void MessageOp::process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event) {
	MessageOp* op = (MessageOp*)user_ctx;
	sal_error_info_set(&op->error_info,SalReasonIOError, "SIP", 503,"IO Error",NULL);
	op->process_error();
}

void MessageOp::process_response_event_cb(void *op_base, const belle_sip_response_event_t *event) {
	MessageOp* op = (MessageOp*)op_base;
	int code = belle_sip_response_get_status_code(belle_sip_response_event_get_response(event));
	SalMessageDeliveryStatus status;
	op->set_error_info_from_response(belle_sip_response_event_get_response(event));
	
	if (code>=100 && code <200)
		status=SalMessageDeliveryInProgress;
	else if (code>=200 && code <300)
		status=SalMessageDeliveryDone;
	else
		status=SalMessageDeliveryFailed;
	
	op->root->callbacks.message_delivery_update(op,status);
}

void MessageOp::process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event) {
	MessageOp* op=(MessageOp*)user_ctx;
	sal_error_info_set(&op->error_info,SalReasonRequestTimeout, "SIP", 408,"Request timeout",NULL);
	op->process_error();
}

bool_t MessageOp::is_external_body(belle_sip_header_content_type_t* content_type) {
	return strcmp("message",belle_sip_header_content_type_get_type(content_type))==0
			&&	strcmp("external-body",belle_sip_header_content_type_get_subtype(content_type))==0;
}

void MessageOp::add_message_accept(belle_sip_message_t *msg) {
	bctbx_list_t *item;
	const char *str;
	char *old;
	char *header = ms_strdup("xml/cipher, application/cipher.vnd.gsma.rcs-ft-http+xml");

	for (item = this->root->supported_content_types; item != NULL; item = bctbx_list_next(item)) {
		str = (const char *)bctbx_list_get_data(item);
		old = header;
		header = ms_strdup_printf("%s, %s", old, str);
		ms_free(old);
	}

	belle_sip_message_add_header(msg, belle_sip_header_create("Accept", header));
	ms_free(header);
}

void MessageOp::process_incoming_message(const belle_sip_request_event_t *event) {
	belle_sip_request_t* req = belle_sip_request_event_get_request(event);
	belle_sip_server_transaction_t* server_transaction = belle_sip_provider_create_server_transaction(this->root->prov,req);
	belle_sip_header_address_t* address;
	belle_sip_header_from_t* from_header;
	belle_sip_header_content_type_t* content_type;
	belle_sip_response_t* resp;
	int errcode = 500;
	belle_sip_header_call_id_t* call_id = belle_sip_message_get_header_by_type(req,belle_sip_header_call_id_t);
	belle_sip_header_cseq_t* cseq = belle_sip_message_get_header_by_type(req,belle_sip_header_cseq_t);
	belle_sip_header_date_t *date=belle_sip_message_get_header_by_type(req,belle_sip_header_date_t);
	char* from;
	bool_t external_body=FALSE;

	from_header=belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(req),belle_sip_header_from_t);
	content_type=belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(req),belle_sip_header_content_type_t);
	
	if (content_type) {
		SalMessage salmsg;
		char message_id[256]={0};

		if (this->pending_server_trans) belle_sip_object_unref(this->pending_server_trans);
		
		this->pending_server_trans=server_transaction;
		belle_sip_object_ref(this->pending_server_trans);

		external_body=is_external_body(content_type);
		address=belle_sip_header_address_create(belle_sip_header_address_get_displayname(BELLE_SIP_HEADER_ADDRESS(from_header))
				,belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(from_header)));
		from=belle_sip_object_to_string(BELLE_SIP_OBJECT(address));
		snprintf(message_id,sizeof(message_id)-1,"%s%i"
				,belle_sip_header_call_id_get_call_id(call_id)
				,belle_sip_header_cseq_get_seq_number(cseq));
		salmsg.from=from;
		/* if we just deciphered a message, use the deciphered part(which can be a rcs xml body pointing to the file to retreive from server)*/
		salmsg.text=(!external_body)?belle_sip_message_get_body(BELLE_SIP_MESSAGE(req)):NULL;
		salmsg.url=NULL;
		salmsg.content_type = ms_strdup_printf("%s/%s", belle_sip_header_content_type_get_type(content_type), belle_sip_header_content_type_get_subtype(content_type));
		if (external_body && belle_sip_parameters_get_parameter(BELLE_SIP_PARAMETERS(content_type),"URL")) {
			size_t url_length=strlen(belle_sip_parameters_get_parameter(BELLE_SIP_PARAMETERS(content_type),"URL"));
			salmsg.url = ms_strdup(belle_sip_parameters_get_parameter(BELLE_SIP_PARAMETERS(content_type),"URL")+1); /* skip first "*/
			((char*)salmsg.url)[url_length-2]='\0'; /*remove trailing "*/
		}
		salmsg.message_id=message_id;
		salmsg.time=date ? belle_sip_header_date_get_time(date) : time(NULL);
		this->root->callbacks.message_received(this,&salmsg);

		belle_sip_object_unref(address);
		belle_sip_free(from);
		if (salmsg.url) ms_free((char*)salmsg.url);
		ms_free((char *)salmsg.content_type);
	} else {
		ms_error("Unsupported MESSAGE (no Content-Type)");
		resp = belle_sip_response_create_from_request(req, errcode);
		add_message_accept((belle_sip_message_t*)resp);
		belle_sip_server_transaction_send_response(server_transaction,resp);
		release();
	}
}

void MessageOp::process_request_event_cb(void *op_base, const belle_sip_request_event_t *event) {
	MessageOp* op = (MessageOp*)op_base;
	op->process_incoming_message(event);
}

void MessageOp::fill_cbs() {
	static belle_sip_listener_callbacks_t op_message_callbacks = {0};
	if (op_message_callbacks.process_io_error==NULL) {
		op_message_callbacks.process_io_error=process_io_error_cb;
		op_message_callbacks.process_response_event=process_response_event_cb;
		op_message_callbacks.process_timeout=process_timeout_cb;
		op_message_callbacks.process_request_event=process_request_event_cb;
	}
	this->callbacks=&op_message_callbacks;
	this->type=Type::Message;
}

int MessageOp::send(const char *from, const char *to, const char* content_type, const char *msg, const char *peer_uri) {
	belle_sip_request_t* req;
	char content_type_raw[256];
	size_t content_length = msg?strlen(msg):0;
	time_t curtime = ms_time(NULL);
	const char *body;
	int retval;
	
	if (this->dialog){
		/*for SIP MESSAGE that are sent in call's dialog*/
		req=belle_sip_dialog_create_queued_request(this->dialog,"MESSAGE");
	}else{
		fill_cbs();
		if (from)
			set_from(from);
		if (to)
			set_to(to);
		this->dir=Dir::Outgoing;

		req=build_request("MESSAGE");
		if (req == NULL ){
			return -1;
		}
		if (get_contact_address()){
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(create_contact()));
		}
	}

	snprintf(content_type_raw,sizeof(content_type_raw),BELLE_SIP_CONTENT_TYPE ": %s",content_type);
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(belle_sip_header_content_type_parse(content_type_raw)));
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(belle_sip_header_content_length_create(content_length)));
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(belle_sip_header_date_create_from_time(&curtime)));
	body = msg;
	if (body){
		/*don't call set_body() with null argument because it resets content type and content length*/
		belle_sip_message_set_body(BELLE_SIP_MESSAGE(req), body, content_length);
	}
	retval = send_request(req);

	return retval;
}

int MessageOp::reply(SalReason reason) {
	if (this->pending_server_trans){
		int code=to_sip_code(reason);
		belle_sip_response_t *resp = belle_sip_response_create_from_request(
			belle_sip_transaction_get_request((belle_sip_transaction_t*)this->pending_server_trans),code);
		belle_sip_server_transaction_send_response(this->pending_server_trans,resp);
		return 0;
	}else ms_error("sal_message_reply(): no server transaction");
	return -1;
}
