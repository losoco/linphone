#include "subscribe_op.hh"

using namespace std;

void SubscribeOp::subscribe_process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event) {
	SubscribeOp *op = (SubscribeOp*)user_ctx;
	belle_sip_object_t *src = belle_sip_io_error_event_get_source(event);
	if (BELLE_SIP_OBJECT_IS_INSTANCE_OF(src, belle_sip_client_transaction_t)){
		belle_sip_client_transaction_t *tr = BELLE_SIP_CLIENT_TRANSACTION(src);
		belle_sip_request_t* req = belle_sip_transaction_get_request((belle_sip_transaction_t*)tr);
		const char *method=belle_sip_request_get_method(req);
	
		if (!op->dialog) {
			/*this is handling outgoing out-of-dialog notifies*/
			if (strcmp(method,"NOTIFY")==0){
				SalErrorInfo *ei=&op->error_info;
				sal_error_info_set(ei,SalReasonIOError, "SIP", 0,NULL,NULL);
				op->root->callbacks.on_notify_response(op);
			}
		}
	}
}

void SubscribeOp::subscribe_response_event_cb(void *op_base, const belle_sip_response_event_t *event){
	SubscribeOp *op = (SubscribeOp*)op_base;
	belle_sip_request_t * req;
	const char *method;
	belle_sip_client_transaction_t *tr =  belle_sip_response_event_get_client_transaction(event);

	if (!tr) return;
	req = belle_sip_transaction_get_request((belle_sip_transaction_t*)tr);
	method = belle_sip_request_get_method(req);
	
	if (!op->dialog) {
		if (strcmp(method,"NOTIFY")==0){
			op->set_error_info_from_response(belle_sip_response_event_get_response(event));
			op->root->callbacks.on_notify_response(op);
		}
	}
}

void SubscribeOp::subscribe_process_timeout(void *user_ctx, const belle_sip_timeout_event_t *event) {
	SubscribeOp *op = (SubscribeOp*)user_ctx;
	belle_sip_request_t * req;
	const char *method;
	belle_sip_client_transaction_t *tr =  belle_sip_timeout_event_get_client_transaction(event);

	if (!tr) return;
	req = belle_sip_transaction_get_request((belle_sip_transaction_t*)tr);
	method = belle_sip_request_get_method(req);
	
	if (!op->dialog) {
		/*this is handling outgoing out-of-dialog notifies*/
		if (strcmp(method,"NOTIFY")==0){
			SalErrorInfo *ei=&op->error_info;
			sal_error_info_set(ei,SalReasonRequestTimeout, "SIP", 0,NULL,NULL);
			op->root->callbacks.on_notify_response(op);
		}
	}
}

void SubscribeOp::handle_notify(belle_sip_request_t *req, const char *eventname, SalBodyHandler* body_handler){
	SalSubscribeStatus sub_state;
	belle_sip_header_subscription_state_t* subscription_state_header=belle_sip_message_get_header_by_type(req,belle_sip_header_subscription_state_t);
	belle_sip_response_t* resp;
	belle_sip_server_transaction_t* server_transaction = this->pending_server_trans;
	
	if (!subscription_state_header || strcasecmp(BELLE_SIP_SUBSCRIPTION_STATE_TERMINATED,belle_sip_header_subscription_state_get_state(subscription_state_header)) ==0) {
		sub_state=SalSubscribeTerminated;
		ms_message("Outgoing subscription terminated by remote [%s]",sal_op_get_to(op));
	} else
		sub_state=SalSubscribeActive;
	ref();
	this->root->callbacks.notify(this,sub_state,eventname,body_handler);
	resp=create_response_from_request(req,200);
	belle_sip_server_transaction_send_response(server_transaction,resp);
	unref();
}

void SubscribeOp::subscribe_process_request_event_cb(void *op_base, const belle_sip_request_event_t *event) {
	SubscribeOp* op = (SubscribeOp*)op_base;
	belle_sip_server_transaction_t* server_transaction = belle_sip_provider_create_server_transaction(op->root->prov,belle_sip_request_event_get_request(event));
	belle_sip_request_t* req = belle_sip_request_event_get_request(event);
	belle_sip_dialog_state_t dialog_state;
	belle_sip_header_expires_t* expires = belle_sip_message_get_header_by_type(req,belle_sip_header_expires_t);
	belle_sip_header_event_t *event_header;
	belle_sip_body_handler_t *body_handler;
	belle_sip_response_t* resp;
	const char *eventname=NULL;
	const char *method=belle_sip_request_get_method(req);
	belle_sip_dialog_t *dialog = NULL;
	
	belle_sip_object_ref(server_transaction);
	if (op->pending_server_trans)  belle_sip_object_unref(op->pending_server_trans);
	op->pending_server_trans=server_transaction;

	event_header=belle_sip_message_get_header_by_type(req,belle_sip_header_event_t);
	body_handler = BELLE_SIP_BODY_HANDLER(op->get_body_handler(BELLE_SIP_MESSAGE(req)));
	
	if (event_header==NULL){
		ms_warning("No event header in incoming SUBSCRIBE.");
		resp=op->create_response_from_request(req,400);
		belle_sip_server_transaction_send_response(server_transaction,resp);
		if (!op->dialog) op->release();
		return;
	}
	if (op->event==NULL) {
		op->event=event_header;
		belle_sip_object_ref(op->event);
	}
	eventname=belle_sip_header_event_get_package_name(event_header);
	
	if (!op->dialog) {
		if (strcmp(method,"SUBSCRIBE")==0){
			dialog = belle_sip_provider_create_dialog(op->root->prov,BELLE_SIP_TRANSACTION(server_transaction));
			if (!dialog){
				resp=op->create_response_from_request(req,481);
				belle_sip_server_transaction_send_response(server_transaction,resp);
				op->release();
				return;
			}
			op->set_or_update_dialog(dialog);
			ms_message("new incoming subscription from [%s] to [%s]",op->get_from(),op->get_to());
		}else{ /*this is a NOTIFY*/
			op->handle_notify(req, eventname, (SalBodyHandler *)body_handler);
			return;
		}
	}
	dialog_state=belle_sip_dialog_get_state(op->dialog);
	switch(dialog_state) {

	case BELLE_SIP_DIALOG_NULL: {
		const char *type = NULL;
		belle_sip_header_content_type_t *content_type = belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(req), belle_sip_header_content_type_t);
		if (content_type) type = belle_sip_header_content_type_get_type(content_type);
		op->root->callbacks.subscribe_received(op, eventname, type ? (SalBodyHandler *)body_handler : NULL);
		break;
	}
	case BELLE_SIP_DIALOG_EARLY:
		ms_error("unexpected method [%s] for dialog [%p] in state BELLE_SIP_DIALOG_EARLY ",belle_sip_request_get_method(req),op->dialog);
		break;

	case BELLE_SIP_DIALOG_CONFIRMED:
		if (strcmp("NOTIFY",method)==0) {
			op->handle_notify(req, eventname, (SalBodyHandler *)body_handler);
		} else if (strcmp("SUBSCRIBE",method)==0) {
			/*either a refresh of an unsubscribe*/
			if (expires && belle_sip_header_expires_get_expires(expires)>0) {
				resp=op->create_response_from_request(req,200);
				belle_sip_server_transaction_send_response(server_transaction,resp);
			} else if(expires) {
				ms_message("Unsubscribe received from [%s]",op->get_from());
				resp=op->create_response_from_request(req,200);
				belle_sip_server_transaction_send_response(server_transaction,resp);
				op->root->callbacks.incoming_subscribe_closed(op);
			}
		}
		break;
		default: {
			ms_error("unexpected dialog state [%s]",belle_sip_dialog_state_to_string(dialog_state));
		}
	}
}

void SubscribeOp::subscribe_process_dialog_terminated_cb(void *ctx, const belle_sip_dialog_terminated_event_t *event) {
	belle_sip_dialog_t *dialog = belle_sip_dialog_terminated_event_get_dialog(event);
	SubscribeOp* op= (SubscribeOp*)ctx;
	if (op->dialog) {
		if (belle_sip_dialog_terminated_event_is_expired(event)){
			if (!belle_sip_dialog_is_server(dialog)){
				/*notify the app that our subscription is dead*/
				const char *eventname = NULL;
				if (op->event){
					eventname = belle_sip_header_event_get_package_name(op->event);
				}
				op->root->callbacks.notify(op, SalSubscribeTerminated, eventname, NULL);
			}else{
				op->root->callbacks.incoming_subscribe_closed(op);
			}
		}
		op->set_or_update_dialog(NULL);
	}
}

void SubscribeOp::release_cb(void *op_base) {
	SubscribeOp *op =(SubscribeOp*)op_base;
	if(op->refresher) {
		belle_sip_refresher_stop(op->refresher);
		belle_sip_object_unref(op->refresher);
		op->refresher=NULL;
		op->set_or_update_dialog(NULL); /*only if we have refresher. else dialog terminated event will remove association*/
	}
}

void SubscribeOp::fill_cbs() {
	static belle_sip_listener_callbacks_t op_subscribe_callbacks={0};
	if (op_subscribe_callbacks.process_io_error==NULL){
		op_subscribe_callbacks.process_io_error=subscribe_process_io_error_cb;
		op_subscribe_callbacks.process_response_event=subscribe_response_event_cb;
		op_subscribe_callbacks.process_timeout=subscribe_process_timeout_cb;
		op_subscribe_callbacks.process_transaction_terminated=subscribe_process_transaction_terminated_cb;
		op_subscribe_callbacks.process_request_event=subscribe_process_request_event_cb;
		op_subscribe_callbacks.process_dialog_terminated=subscribe_process_dialog_terminated_cb;
	}
	this->callbacks=&op_subscribe_callbacks;
	this->type=Type::Subscribe;
	this->release_cb=release_cb;
}

void SubscribeOp::subscribe_refresher_listener_cb (belle_sip_refresher_t* refresher,void* user_pointer,unsigned int status_code,const char* reason_phrase, int will_retry) {
	SubscribeOp* op = (SubscribeOp*)user_pointer;
	belle_sip_transaction_t *tr=BELLE_SIP_TRANSACTION(belle_sip_refresher_get_transaction(refresher));
	/*belle_sip_response_t* response=belle_sip_transaction_get_response(tr);*/
	SalSubscribeStatus sss=SalSubscribeTerminated;
	
	ms_message("Subscribe refresher  [%i] reason [%s] ",status_code,reason_phrase?reason_phrase:"none");
	if (status_code>=200 && status_code<300){
		if (status_code==200) sss=SalSubscribeActive;
		else if (status_code==202) sss=SalSubscribePending;
		op->set_or_update_dialog(belle_sip_transaction_get_dialog(tr));
		op->root->callbacks.subscribe_response(op,sss, will_retry);
	} else if (status_code >= 300) {
		SalReason reason = SalReasonUnknown;
		if (status_code == 503) { /*refresher returns 503 for IO error*/
			reason = SalReasonIOError;
		}
		sal_error_info_set(&op->error_info, reason, "SIP", status_code,reason_phrase,NULL);
		op->root->callbacks.subscribe_response(op,sss, will_retry);
	}else if (status_code==0){
		op->root->callbacks.on_expire(op);
	}
	
}

int SubscribeOp::subscribe(const char *from, const char *to, const char *eventname, int expires, const SalBodyHandler *body_handler) {
	belle_sip_request_t *req=NULL;
	
	if (from)
		set_from(from);
	if (to)
		set_to(to);
	
	if (!this->dialog){
		fill_cbs();
		req=build_request("SUBSCRIBE");
		if( req == NULL ) {
			return -1;
		}
		set_event(eventname);
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(this->event));
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(belle_sip_header_expires_create(expires)));
		belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(req), BELLE_SIP_BODY_HANDLER(body_handler));
		return sal_op_send_and_create_refresher(op,req,expires,subscribe_refresher_listener_cb);
	}else if (this->refresher){
		const belle_sip_transaction_t *tr=(const belle_sip_transaction_t*) belle_sip_refresher_get_transaction(this->refresher);
		belle_sip_request_t *last_req=belle_sip_transaction_get_request(tr);
		/* modify last request to update body*/
		belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(last_req), BELLE_SIP_BODY_HANDLER(body_handler));
		return belle_sip_refresher_refresh(this->refresher,expires);
	}
	ms_warning("sal_subscribe(): no dialog and no refresher ?");
	return -1;
}

int SubscribeOp::unsubscribe() {
	if (this->refresher){
		const belle_sip_transaction_t *tr=(const belle_sip_transaction_t*) belle_sip_refresher_get_transaction(this->refresher);
		belle_sip_request_t *last_req=belle_sip_transaction_get_request(tr);
		belle_sip_message_set_body(BELLE_SIP_MESSAGE(last_req), NULL, 0);
		belle_sip_refresher_refresh(this->refresher,0);
		return 0;
	}
	return -1;
}

int SubscribeOp::accept() {
	belle_sip_request_t* req=belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(this->pending_server_trans));
	belle_sip_header_expires_t* expires = belle_sip_message_get_header_by_type(req,belle_sip_header_expires_t);
	belle_sip_response_t* resp = create_response_from_request(req,200);
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp),BELLE_SIP_HEADER(expires));
	belle_sip_server_transaction_send_response(this->pending_server_trans,resp);
	return 0;
}

int SubscribeOp::decline(SalReason reason) {
	belle_sip_response_t*  resp = belle_sip_response_create_from_request(belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(this->pending_server_trans)),
									   to_sip_code(reason));
	belle_sip_server_transaction_send_response(this->pending_server_trans,resp);
	return 0;
}

int SubscribeOp::notify_pending_state() {
	
	if (this->dialog != NULL && this->pending_server_trans) {
		belle_sip_request_t* notify;
		belle_sip_header_subscription_state_t* sub_state;
		ms_message("Sending NOTIFY with subscription state pending for op [%p]", this);
		if (!(notify=belle_sip_dialog_create_request(this->dialog,"NOTIFY"))) {
			ms_error("Cannot create NOTIFY on op [%p]", this);
			return -1;
		}
		if (this->event) belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify),BELLE_SIP_HEADER(this->event));
		sub_state=belle_sip_header_subscription_state_new();
		belle_sip_header_subscription_state_set_state(sub_state,BELLE_SIP_SUBSCRIPTION_STATE_PENDING);
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(sub_state));
		return sal_op_send_request(op,notify);
	} else {
		ms_warning("NOTIFY with subscription state pending for op [%p] not implemented in this case (either dialog pending trans does not exist", this);
	}
	
	return 0;
}
