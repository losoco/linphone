#include "publish_op.hh"

using namespace std;

void PublishOp::publish_response_event_cb(void *userctx, const belle_sip_response_event_t *event) {
	PublishOp *op=(PublishOp*)userctx;
	op->set_error_info_from_response(belle_sip_response_event_get_response(event));
	if (op->error_info.protocol_code>=200){
		op->root->callbacks.on_publish_response(op);
	}
}

void PublishOp::fill_cbs() {
	static belle_sip_listener_callbacks_t op_publish_callbacks={0};
	if (op_publish_callbacks.process_response_event==NULL){
		op_publish_callbacks.process_response_event=publish_response_event_cb;
	}
	
	this->callbacks=&op_publish_callbacks;
	this->type=Type::Publish;
}

void PublishOp::publish_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry) {
	PublishOp* op = (PublishOp*)user_pointer;
	const belle_sip_client_transaction_t* last_publish_trans=belle_sip_refresher_get_transaction(op->refresher);
	belle_sip_response_t *response=belle_sip_transaction_get_response(BELLE_SIP_TRANSACTION(last_publish_trans));
	ms_message("Publish refresher  [%i] reason [%s] for proxy [%s]",status_code,reason_phrase?reason_phrase:"none",op->get_proxy());
	if (status_code==0){
		op->root->callbacks.on_expire(op);
	}else if (status_code>=200){
		belle_sip_header_t *sip_etag;
		const char *sip_etag_string = NULL;
		if (response && (sip_etag = belle_sip_message_get_header(BELLE_SIP_MESSAGE(response), "SIP-ETag"))) {
			sip_etag_string = belle_sip_header_get_unparsed_value(sip_etag);
		}
		op->set_entity_tag(sip_etag_string);
		sal_error_info_set(&op->error_info,SalReasonUnknown, "SIP", status_code,reason_phrase,NULL);
		op->assign_recv_headers((belle_sip_message_t*)response);
		op->root->callbacks.on_publish_response(op);
	}
}

int PublishOp::publish(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler) {
	belle_sip_request_t *req=NULL;
	if(!this->refresher || !belle_sip_refresher_get_transaction(this->refresher)) {
		if (from)
			set_from(from);
		if (to)
			set_to(to);

		fill_cbs();
		req=build_request("PUBLISH");
		if( req == NULL ){
			return -1;
		}
		
		if (get_entity_tag()) {
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),belle_sip_header_create("SIP-If-Match", get_entity_tag()));
		}
		
		if (get_contact_address()){
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(create_contact()));
		}
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),belle_sip_header_create("Event",eventname));
		belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(req), BELLE_SIP_BODY_HANDLER(body_handler));
		if (expires!=-1)
			return send_and_create_refresher(req,expires,publish_refresher_listener_cb);
		else return send_request(req);
	} else {
		/*update status*/
		const belle_sip_client_transaction_t* last_publish_trans=belle_sip_refresher_get_transaction(this->refresher);
		belle_sip_request_t* last_publish=belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(last_publish_trans));
		/*update body*/
		if (expires == 0) {
			belle_sip_message_set_body(BELLE_SIP_MESSAGE(last_publish), NULL, 0);
		} else {
			belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(last_publish), BELLE_SIP_BODY_HANDLER(body_handler));
		}
		return belle_sip_refresher_refresh(this->refresher,expires==-1 ? BELLE_SIP_REFRESHER_REUSE_EXPIRES : expires);
	}
}

int PublishOp::unpublish() {
	if (this->refresher){
		const belle_sip_transaction_t *tr=(const belle_sip_transaction_t*) belle_sip_refresher_get_transaction(this->refresher);
		belle_sip_request_t *last_req=belle_sip_transaction_get_request(tr);
		belle_sip_message_set_body(BELLE_SIP_MESSAGE(last_req), NULL, 0);
		belle_sip_refresher_refresh(this->refresher,0);
		return 0;
	}
	return -1;
}
