#include "sal/sal.hh"
#include "bellesip_sal/sal_impl.h"

using namespace std;

/**********************/
/* Sal implementation */
/**********************/

Sal::~Sal() {
	belle_sip_object_unref(this->user_agent);
	belle_sip_object_unref(this->prov);
	belle_sip_object_unref(this->stack);
	belle_sip_object_unref(this->listener);
	if (this->supported) belle_sip_object_unref(this->supported);
	bctbx_list_free_with_data(this->supported_tags,ms_free);
	bctbx_list_free_with_data(this->supported_content_types, ms_free);
	if (this->uuid) ms_free(this->uuid);
	if (this->root_ca) ms_free(this->root_ca);
	if (this->root_ca_data) ms_free(this->root_ca_data);
}

void Sal::set_callbacks(const SalCallbacks *cbs) {
	memcpy(&this->callbacks,cbs,sizeof(*cbs));
	if (this->callbacks.call_received==NULL)
		this->callbacks.call_received=(SalOnCallReceived)unimplemented_stub;
	if (this->callbacks.call_ringing==NULL)
		this->callbacks.call_ringing=(SalOnCallRinging)unimplemented_stub;
	if (this->callbacks.call_accepted==NULL)
		this->callbacks.call_accepted=(SalOnCallAccepted)unimplemented_stub;
	if (this->callbacks.call_failure==NULL)
		this->callbacks.call_failure=(SalOnCallFailure)unimplemented_stub;
	if (this->callbacks.call_terminated==NULL)
		this->callbacks.call_terminated=(SalOnCallTerminated)unimplemented_stub;
	if (this->callbacks.call_released==NULL)
		this->callbacks.call_released=(SalOnCallReleased)unimplemented_stub;
	if (this->callbacks.call_updating==NULL)
		this->callbacks.call_updating=(SalOnCallUpdating)unimplemented_stub;
	if (this->callbacks.auth_failure==NULL)
		this->callbacks.auth_failure=(SalOnAuthFailure)unimplemented_stub;
	if (this->callbacks.register_success==NULL)
		this->callbacks.register_success=(SalOnRegisterSuccess)unimplemented_stub;
	if (this->callbacks.register_failure==NULL)
		this->callbacks.register_failure=(SalOnRegisterFailure)unimplemented_stub;
	if (this->callbacks.dtmf_received==NULL)
		this->callbacks.dtmf_received=(SalOnDtmfReceived)unimplemented_stub;
	if (this->callbacks.notify==NULL)
		this->callbacks.notify=(SalOnNotify)unimplemented_stub;
	if (this->callbacks.subscribe_received==NULL)
		this->callbacks.subscribe_received=(SalOnSubscribeReceived)unimplemented_stub;
	if (this->callbacks.incoming_subscribe_closed==NULL)
		this->callbacks.incoming_subscribe_closed=(SalOnIncomingSubscribeClosed)unimplemented_stub;
	if (this->callbacks.parse_presence_requested==NULL)
		this->callbacks.parse_presence_requested=(SalOnParsePresenceRequested)unimplemented_stub;
	if (this->callbacks.convert_presence_to_xml_requested==NULL)
		this->callbacks.convert_presence_to_xml_requested=(SalOnConvertPresenceToXMLRequested)unimplemented_stub;
	if (this->callbacks.notify_presence==NULL)
		this->callbacks.notify_presence=(SalOnNotifyPresence)unimplemented_stub;
	if (this->callbacks.subscribe_presence_received==NULL)
		this->callbacks.subscribe_presence_received=(SalOnSubscribePresenceReceived)unimplemented_stub;
	if (this->callbacks.message_received==NULL)
		this->callbacks.message_received=(SalOnMessageReceived)unimplemented_stub;
	if (this->callbacks.ping_reply==NULL)
		this->callbacks.ping_reply=(SalOnPingReply)unimplemented_stub;
	if (this->callbacks.auth_requested==NULL)
		this->callbacks.auth_requested=(SalOnAuthRequested)unimplemented_stub;
	if (this->callbacks.info_received==NULL)
		this->callbacks.info_received=(SalOnInfoReceived)unimplemented_stub;
	if (this->callbacks.on_publish_response==NULL)
		this->callbacks.on_publish_response=(SalOnPublishResponse)unimplemented_stub;
	if (this->callbacks.on_expire==NULL)
		this->callbacks.on_expire=(SalOnExpire)unimplemented_stub;
}

void Sal::set_tls_properties(){
	belle_sip_listening_point_t *lp=belle_sip_provider_get_listening_point(this->prov,"TLS");
	if (lp){
		belle_sip_tls_listening_point_t *tlp=BELLE_SIP_TLS_LISTENING_POINT(lp);
		belle_tls_crypto_config_t *crypto_config = belle_tls_crypto_config_new();
		int verify_exceptions = BELLE_TLS_VERIFY_NONE;
		if (!this->tls_verify) verify_exceptions = BELLE_TLS_VERIFY_ANY_REASON;
		else if (!this->tls_verify_cn) verify_exceptions = BELLE_TLS_VERIFY_CN_MISMATCH;
		belle_tls_crypto_config_set_verify_exceptions(crypto_config, verify_exceptions);
		if (this->root_ca != NULL) belle_tls_crypto_config_set_root_ca(crypto_config, this->root_ca);
		if (this->root_ca_data != NULL) belle_tls_crypto_config_set_root_ca_data(crypto_config, this->root_ca_data);
		if (this->ssl_config != NULL) belle_tls_crypto_config_set_ssl_config(crypto_config, this->ssl_config);
		belle_sip_tls_listening_point_set_crypto_config(tlp, crypto_config);
		belle_sip_object_unref(crypto_config);
	}
}

int Sal::add_listen_port(SalAddress* addr, bool_t is_tunneled) {
	int result;
	belle_sip_listening_point_t* lp;
	if (is_tunneled){
#ifdef TUNNEL_ENABLED
		if (sal_address_get_transport(addr)!=SalTransportUDP){
			ms_error("Tunneled mode is only available for UDP kind of transports.");
			return -1;
		}
		lp = belle_sip_tunnel_listening_point_new(this->stack, this->tunnel_client);
		if (!lp){
			ms_error("Could not create tunnel listening point.");
			return -1;
		}
#else
		ms_error("No tunnel support in library.");
		return -1;
#endif
	}else{
		lp = belle_sip_stack_create_listening_point(this->stack,
									sal_address_get_domain(addr),
									sal_address_get_port(addr),
									sal_transport_to_string(sal_address_get_transport(addr)));
	}
	if (lp) {
		belle_sip_listening_point_set_keep_alive(lp,this->keep_alive);
		result = belle_sip_provider_add_listening_point(this->prov,lp);
		if (sal_address_get_transport(addr)==SalTransportTLS) {
			set_tls_properties();
		}
	} else {
		return -1;
	}
	return result;
}

int Sal::set_listen_port(const char *addr, int port, SalTransport tr, int is_tunneled) {
	SalAddress* sal_addr = sal_address_new(NULL);
	int result;
	sal_address_set_domain(sal_addr,addr);
	sal_address_set_port(sal_addr,port);
	sal_address_set_transport(sal_addr,tr);
	result = add_listen_port(sal_addr, is_tunneled);
	sal_address_destroy(sal_addr);
	return result;
}

int Sal::get_listening_port(SalTransport tr){
	const char *tpn=sal_transport_to_string(tr);
	belle_sip_listening_point_t *lp=belle_sip_provider_get_listening_point(this->prov, tpn);
	if (lp){
		return belle_sip_listening_point_get_port(lp);
	}
	return 0;
}

int Sal::sal_unlisten_ports(){
	const belle_sip_list_t * lps = belle_sip_provider_get_listening_points(this->prov);
	belle_sip_list_t * tmp_list = belle_sip_list_copy(lps);
	belle_sip_list_for_each2 (tmp_list,(void (*)(void*,void*))remove_listening_point,this->prov);
	belle_sip_list_free(tmp_list);
	ms_message("sal_unlisten_ports done");
	return 0;
}

int Sal::transport_available(SalTransport t) {
	switch(t){
		case SalTransportUDP:
		case SalTransportTCP:
			return TRUE;
		case SalTransportTLS:
			return belle_sip_stack_tls_available(this->stack);
		case SalTransportDTLS:
			return FALSE;
	}
	return FALSE;
}

void Sal::make_supported_header(){
	bctbx_list_t *it;
	char *alltags=NULL;
	size_t buflen=64;
	size_t written=0;

	if (this->supported){
		belle_sip_object_unref(this->supported);
		this->supported=NULL;
	}
	for(it=this->supported_tags;it!=NULL;it=it->next){
		const char *tag=(const char*)it->data;
		size_t taglen=strlen(tag);
		if (alltags==NULL || (written+taglen+1>=buflen)) alltags=reinterpret_cast<char *>(ms_realloc(alltags,(buflen=buflen*2)));
		written+=snprintf(alltags+written,buflen-written,it->next ? "%s, " : "%s",tag);
	}
	if (alltags){
		this->supported=belle_sip_header_create("Supported",alltags);
		if (this->supported){
			belle_sip_object_ref(this->supported);
		}
		ms_free(alltags);
	}
}

void Sal::set_supported_tags(const char* tags){
	this->supported_tags=bctbx_list_free_with_data(this->supported_tags,ms_free);
	if (tags){
		char *iter;
		char *buffer=ms_strdup(tags);
		char *tag;
		char *context=NULL;
		iter=buffer;
		while((tag=strtok_r(iter,", ",&context))!=NULL){
			iter=NULL;
			this->supported_tags=bctbx_list_append(this->supported_tags,ms_strdup(tag));
		}
		ms_free(buffer);
	}
	make_supported_header();
}

void Sal::add_supported_tag(const char* tag){
	bctbx_list_t *elem=bctbx_list_find_custom(this->supported_tags,(bctbx_compare_func)strcasecmp,tag);
	if (!elem){
		this->supported_tags=bctbx_list_append(this->supported_tags,ms_strdup(tag));
		make_supported_header();
	}
}

void Sal::remove_supported_tag(const char* tag){
	bctbx_list_t *elem=bctbx_list_find_custom(this->supported_tags,(bctbx_compare_func)strcasecmp,tag);
	if (elem){
		ms_free(elem->data);
		this->supported_tags=bctbx_list_erase_link(this->supported_tags,elem);
		make_supported_header();
	}
}

int Sal::reset_transports() {
	ms_message("Reseting transports");
	belle_sip_provider_clean_channels(this->prov);
	return 0;
}

ortp_socket_t Sal::get_socket() const {
	ms_warning("sal_get_socket is deprecated");
	return -1;
}

void Sal::set_user_agent(const char *user_agent) {
	belle_sip_header_user_agent_set_products(this->user_agent,NULL);
	belle_sip_header_user_agent_add_product(this->user_agent,user_agent);
}

const char* Sal::get_user_agent() const {
	static char user_agent[255];
	belle_sip_header_user_agent_get_products_as_string(this->user_agent, user_agent, 254);
	return user_agent;
}

void Sal::append_stack_string_to_user_agent() {
	char stack_string[64];
	snprintf(stack_string, sizeof(stack_string) - 1, "(belle-sip/%s)", belle_sip_version_to_string());
	belle_sip_header_user_agent_add_product(this->user_agent, stack_string);
}

void Sal::set_keepalive_period(unsigned int value) {
	const belle_sip_list_t* iterator;
	belle_sip_listening_point_t* lp;
	this->keep_alive=value;
	for (iterator=belle_sip_provider_get_listening_points(this->prov);iterator!=NULL;iterator=iterator->next) {
		lp=(belle_sip_listening_point_t*)iterator->data;
		if (this->use_tcp_tls_keep_alive || strcasecmp(belle_sip_listening_point_get_transport(lp),"udp")==0) {
			belle_sip_listening_point_set_keep_alive(lp,this->keep_alive);
		}
	}
}

int Sal::set_tunnel(void *tunnelclient) {
#ifdef TUNNEL_ENABLED
	this->tunnel_client=tunnelclient;
	return 0;
#else
	return -1;
#endif
}

bool_t Sal::is_content_type_supported(const char *content_type) const {
	bctbx_list_t *item;
	for (item = this->supported_content_types; item != NULL; item = bctbx_list_next(item)) {
		const char *item_content_type = (const char *)bctbx_list_get_data(item);
		if (strcmp(item_content_type, content_type) == 0) return TRUE;
	}
	return FALSE;
}

void Sal::add_content_type_support(const char *content_type) {
	if ((content_type != NULL) && (is_content_type_supported(content_type) == FALSE)) {
		this->supported_content_types = bctbx_list_append(this->supported_content_types, ms_strdup(content_type));
	}
}

void Sal::use_rport(bool_t use_rports) {
	belle_sip_provider_enable_rport(this->prov,use_rports);
	ms_message("Sal use rport [%s]", use_rports ? "enabled" : "disabled");
}

void Sal::set_root_ca(const char* rootCa) {
	if (this->root_ca) {
		ms_free(this->root_ca);
		this->root_ca = NULL;
	}
	if (rootCa)
		this->root_ca = ms_strdup(rootCa);
	set_tls_properties();
}

void Sal::set_root_ca_data(const char* data) {
	if (this->root_ca_data) {
		ms_free(this->root_ca_data);
		this->root_ca_data = NULL;
	}
	if (data)
		this->root_ca_data = ms_strdup(data);
	set_tls_properties();
}

void Sal::verify_server_certificates(bool_t verify) {
	this->tls_verify=verify;
	set_tls_properties();
}

void Sal::verify_server_cn(bool_t verify) {
	this->tls_verify_cn = verify;
	set_tls_properties();
}

void Sal::set_ssl_config(void *ssl_config) {
	this->ssl_config = ssl_config;
	set_tls_properties();
}

void Sal::set_uuid(const char *uuid){
	if (this->uuid){
		ms_free(this->uuid);
		this->uuid=NULL;
	}
	if (uuid)
		this->uuid=ms_strdup(uuid);
}

int Sal::create_uuid(char *uuid, size_t len) {
	if (sal_generate_uuid(uuid, len) == 0) {
		set_uuid(uuid);
		return 0;
	}
	return -1;
}

int Sal::generate_uuid(char *uuid, size_t len) {
	sal_uuid_t uuid_struct;
	int i;
	int written;

	if (len==0) return -1;
	/*create an UUID as described in RFC4122, 4.4 */
	belle_sip_random_bytes((unsigned char*)&uuid_struct, sizeof(sal_uuid_t));
	uuid_struct.clock_seq_hi_and_reserved&=~(1<<6);
	uuid_struct.clock_seq_hi_and_reserved|=1<<7;
	uuid_struct.time_hi_and_version&=~(0xf<<12);
	uuid_struct.time_hi_and_version|=4<<12;

	written=snprintf(uuid,len,"%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", uuid_struct.time_low, uuid_struct.time_mid,
			uuid_struct.time_hi_and_version, uuid_struct.clock_seq_hi_and_reserved,
			uuid_struct.clock_seq_low);
	if ((written < 0) || ((size_t)written > (len +13))) {
		ms_error("sal_create_uuid(): buffer is too short !");
		return -1;
	}
	for (i = 0; i < 6; i++)
		written+=snprintf(uuid+written,len-written,"%2.2x", uuid_struct.node[i]);
	uuid[len-1]='\0';
	return 0;
}

void Sal::add_pending_auth(SalOp *op){
	if (bctbx_list_find(this->pending_auths,op)==NULL){
		this->pending_auths=bctbx_list_append(this->pending_auths,op);
		op->has_auth_pending=TRUE;
	}
}

void Sal::remove_pending_auth(SalOp *op){
	if (op->has_auth_pending){
		op->has_auth_pending=FALSE;
		if (bctbx_list_find(this->pending_auths,op)){
			this->pending_auths=bctbx_list_remove(this->pending_auths,op);
		}
	}
}

void Sal::set_default_sdp_handling(SalOpSDPHandling sdp_handling_method)  {
	if (sdp_handling_method != SalOpSDPNormal ) ms_message("Enabling special SDP handling for all new SalOp in Sal[%p]!", this);
	this->default_sdp_handling = sdp_handling_method;
}


/************************/
/* SalOp implementation */
/************************/

SalOp::SalOp(Sal *sal) {
	this->root = sal;
	this->sdp_handling = sal->default_sdp_handling;
	ref();
}

SalOp::~SalOp() {
	if (this->from_address){
		sal_address_destroy(this->from_address);
		this->from_address=NULL;
	}
	if (this->to_address){
		sal_address_destroy(this->to_address);
		this->to_address=NULL;
	}

	if (this->service_route){
		sal_address_destroy(this->service_route);
		this->service_route=NULL;
	}

	if (this->origin_address){
		sal_address_destroy(this->origin_address);
		this->origin_address=NULL;
	}

	if (this->from) {
		ms_free(this->from);
		this->from=NULL;
	}
	if (this->to) {
		ms_free(this->to);
		this->to=NULL;
	}
	if (this->route) {
		ms_free(this->route);
		this->route=NULL;
	}
	if (this->realm) {
		ms_free(this->realm);
		this->realm=NULL;
	}
	if (this->contact_address) {
		sal_address_destroy(this->contact_address);
	}
	if (this->origin){
		ms_free(this->origin);
		this->origin=NULL;
	}
	if (this->remote_ua){
		ms_free(this->remote_ua);
		this->remote_ua=NULL;
	}
	if (this->remote_contact){
		ms_free(this->remote_contact);
		this->remote_contact=NULL;
	}
	if (this->remote_contact_address){
		sal_address_destroy(this->remote_contact_address);
	}
	if (this->local_media)
		sal_media_description_unref(this->local_media);
	if (this->remote_media)
		sal_media_description_unref(this->remote_media);
	if (this->custom_body) {
		sal_custom_body_unref(this->custom_body);
	}
	if (this->call_id)
		ms_free((void *)this->call_id);
	if (this->service_route) {
		sal_address_destroy(this->service_route);
	}
	if (this->route_addresses){
		bctbx_list_for_each(this->route_addresses,(void (*)(void*)) sal_address_destroy);
		this->route_addresses=bctbx_list_free(this->route_addresses);
	}
	if (this->recv_custom_headers)
		sal_custom_header_free(this->recv_custom_headers);
	if (this->sent_custom_headers)
		sal_custom_header_free(this->sent_custom_headers);

	if (this->entity_tag != NULL){
		ms_free(this->entity_tag);
		this->entity_tag = NULL;
	}
}

SalOp *SalOp::ref() {
	_ref++;
	return this;
}

void *SalOp::unref() {
	_ref--;
	if (_ref==0) {
		release_impl();
	} else if (_ref<0) {
		ms_fatal("SalOp [%p]: too many unrefs.",this);
	}
	return NULL;
}

void SalOp::set_contact_address(const SalAddress *address) {
	if (this->contact_address) sal_address_destroy(this->contact_address);
	this->contact_address=address?sal_address_clone(address):NULL;
}

void SalOp::set_and_clean_contact_address(SalAddress *contact) {
	if (contact){
		SalTransport tport = sal_address_get_transport(contact);
		const char* gruu = bctbx_strdup(sal_address_get_uri_param(contact, "gr"));
		sal_address_clean(contact); /* clean out contact_params that come from proxy config*/
		sal_address_set_transport(contact,tport);
		if(gruu)
			sal_address_set_uri_param(contact, "gr", gruu);
		set_contact_address(contact);
		sal_address_unref(contact);
	}
}

void SalOp::assign_address(SalAddress** address, const char *value) {
	if (*address){
		sal_address_destroy(*address);
		*address=NULL;
	}
	if (value)
		*address=sal_address_new(value);
}

void SalOp::assign_string(char **str, const char *arg) {
	if (*str){
		ms_free(*str);
		*str=NULL;
	}
	if (arg)
		*str=ms_strdup(arg);
}

void SalOp::set_route(const char *route) {
	char* route_string=NULL;
	if (this->route_addresses) {
		bctbx_list_for_each(this->route_addresses,(void (*)(void *))sal_address_destroy);
		this->route_addresses=bctbx_list_free(this->route_addresses);
	}
	if (route) {
		this->route_addresses=bctbx_list_append(NULL,NULL);
		assign_address((SalAddress**)&(this->route_addresses->data),route);
		route_string=sal_address_as_string((SalAddress*)this->route_addresses->data);
	}
	assign_string(&this->route,route_string);
	if(route_string) ms_free(route_string);
}

void SalOp::set_route_address(const SalAddress *address){
	char* address_string=sal_address_as_string(address); /*can probably be optimized*/
	set_route(address_string);
	ms_free(address_string);
}

void SalOp::add_route_address(const SalAddress *address) {
	if (this->route_addresses) {
		this->route_addresses=bctbx_list_append(this->route_addresses,(void*)sal_address_clone(address));
	} else {
		set_route_address(address);
	}
}

void SalOp::set_realm(const char *realm) {
	if (this->realm != NULL){
		ms_free(this->realm);
	}
	this->realm = ms_strdup(realm);
}

#define SET_PARAM(name) \
		char* name##_string=NULL; \
		assign_address(&this->name##_address,name); \
		if (this->name##_address) { \
			name##_string=sal_address_as_string(this->name##_address); \
		}\
		assign_string(&this->name,name##_string); \
		if(name##_string) ms_free(name##_string);

void SalOp::set_from(const char *from){
	SET_PARAM(from);
}

void SalOp::set_from_address(const SalAddress *from) {
	char* address_string=sal_address_as_string(from); /*can probably be optimized*/
	set_from(address_string);
	ms_free(address_string);
}

void SalOp::set_to(const char *to) {
	SET_PARAM(to);
}

void SalOp::set_to_address(const SalAddress *to) {
	char* address_string=sal_address_as_string(to); /*can probably be optimized*/
	set_to(address_string);
	ms_free(address_string);
}

void SalOp::set_diversion_address(const SalAddress *diversion) {
	if (this->diversion_address) sal_address_destroy(this->diversion_address);
	this->diversion_address=diversion ? sal_address_clone(diversion) : NULL;
}

int SalOp::refresh() {
	if (this->refresher) {
		belle_sip_refresher_refresh(this->refresher,belle_sip_refresher_get_expires(this->refresher));
		return 0;
	}
	ms_warning("sal_refresh on op [%p] of type [%s] no refresher",op,sal_op_type_to_string(this->type));
	return -1;
}

void SalOp::kill_dialog() {
	ms_warning("op [%p]: force kill of dialog [%p]", this, this->dialog);
	belle_sip_dialog_delete(this->dialog);
}

void SalOp::release() {
	/*if in terminating state, keep this state because it means we are waiting for a response to be able to terminate the operation.*/
	if (this->state!=State::Terminating)
		this->state=State::Terminated;
	set_user_pointer(NULL);/*mandatory because releasing op doesn't not mean freeing op. Make sure back pointer will not be used later*/
	if (this->release_cb)
		this->release_cb(this);
	if (this->refresher) {
		belle_sip_refresher_stop(this->refresher);
	}
	this->op_released = TRUE;
	unref();
}

void SalOp::release_impl(){
	ms_message("Destroying op [%p] of type [%s]",this,sal_op_type_to_string(this->type));
	if (this->pending_auth_transaction) belle_sip_object_unref(this->pending_auth_transaction);
	this->root->remove_pending_auth(this);
	if (this->auth_info) {
		sal_auth_info_delete(this->auth_info);
	}
	if (this->sdp_answer) belle_sip_object_unref(this->sdp_answer);
	if (this->refresher) {
		belle_sip_object_unref(this->refresher);
		this->refresher=NULL;
	}
	if (this->result)
		sal_media_description_unref(this->result);
	if(this->replaces) belle_sip_object_unref(this->replaces);
	if(this->referred_by) belle_sip_object_unref(this->referred_by);

	if (this->pending_client_trans) belle_sip_object_unref(this->pending_client_trans);
	if (this->pending_server_trans) belle_sip_object_unref(this->pending_server_trans);
	if (this->pending_update_server_trans) belle_sip_object_unref(this->pending_update_server_trans);
	if (this->event) belle_sip_object_unref(this->event);
	sal_error_info_reset(&this->error_info);
	delete this;
}

int SalOp::send_request_with_contact(belle_sip_request_t* request, bool_t add_contact) {
	belle_sip_client_transaction_t* client_transaction;
	belle_sip_provider_t* prov=this->root->prov;
	belle_sip_uri_t* outbound_proxy=NULL;
	belle_sip_header_contact_t* contact;
	int result =-1;
	belle_sip_uri_t *next_hop_uri=NULL;

	if (add_contact && !belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request),belle_sip_header_contact_t)) {
		contact = sal_op_create_contact(this);
		belle_sip_message_set_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_HEADER(contact));
	} /*keep existing*/

	_sal_op_add_custom_headers(this, (belle_sip_message_t*)request);

	if (!this->dialog || belle_sip_dialog_get_state(this->dialog) == BELLE_SIP_DIALOG_NULL) {
		/*don't put route header if  dialog is in confirmed state*/
		const MSList *elem=sal_op_get_route_addresses(this);
		const char *transport;
		const char *method=belle_sip_request_get_method(request);
		belle_sip_listening_point_t *udplp=belle_sip_provider_get_listening_point(prov,"UDP");

		if (elem) {
			outbound_proxy=belle_sip_header_address_get_uri((belle_sip_header_address_t*)elem->data);
			next_hop_uri=outbound_proxy;
		}else{
			next_hop_uri=(belle_sip_uri_t*)belle_sip_object_clone((belle_sip_object_t*)belle_sip_request_get_uri(request));
		}
		transport=belle_sip_uri_get_transport_param(next_hop_uri);
		if (transport==NULL){
			/*compatibility mode: by default it should be udp as not explicitely set and if no udp listening point is available, then use
			 * the first available transport*/
			if (!belle_sip_uri_is_secure(next_hop_uri)){
				if (udplp==NULL){
					if (belle_sip_provider_get_listening_point(prov,"TCP")!=NULL){
						transport="tcp";
					}else if (belle_sip_provider_get_listening_point(prov,"TLS")!=NULL ){
						transport="tls";
					}
				}
				if (transport){
					belle_sip_message("Transport is not specified, using %s because UDP is not available.",transport);
					belle_sip_uri_set_transport_param(next_hop_uri,transport);
				}
			}
		}else{
#ifdef TUNNEL_ENABLED
			if (udplp && BELLE_SIP_OBJECT_IS_INSTANCE_OF(udplp,belle_sip_tunnel_listening_point_t)){
				/* our tunnel mode only supports UDP. Force transport to be set to UDP */
				belle_sip_uri_set_transport_param(next_hop_uri,"udp");
			}
#endif
		}
		/*because in case of tunnel, transport can be changed*/
		transport=belle_sip_uri_get_transport_param(next_hop_uri);
		
		if ((strcmp(method,"REGISTER")==0 || strcmp(method,"SUBSCRIBE")==0) && transport &&
			(strcasecmp(transport,"TCP")==0 || strcasecmp(transport,"TLS")==0)){
			/*RFC 5923: add 'alias' parameter to tell the server that we want it to keep the connection for future requests*/
			belle_sip_header_via_t *via=belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request),belle_sip_header_via_t);
			belle_sip_parameters_set_parameter(BELLE_SIP_PARAMETERS(via),"alias",NULL);
		}
	}

	client_transaction = belle_sip_provider_create_client_transaction(prov,request);
	belle_sip_transaction_set_application_data(BELLE_SIP_TRANSACTION(client_transaction),ref());
	if (this->pending_client_trans) belle_sip_object_unref(this->pending_client_trans);
	
	this->pending_client_trans=client_transaction; /*update pending inv for being able to cancel*/
	belle_sip_object_ref(this->pending_client_trans);

	if (belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request),belle_sip_header_user_agent_t)==NULL)
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_HEADER(op->base.root->user_agent));

	if (!belle_sip_message_get_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_AUTHORIZATION)
		&& !belle_sip_message_get_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_PROXY_AUTHORIZATION)) {
		/*hmm just in case we already have authentication param in cache*/
		belle_sip_provider_add_authorization(op->base.root->prov,request,NULL,NULL,NULL,op->base.realm);
	}
	result = belle_sip_client_transaction_send_request_to(client_transaction,next_hop_uri/*might be null*/);

	/*update call id if not set yet for this OP*/
	if (result == 0 && !op->base.call_id) {
		this->call_id=ms_strdup(belle_sip_header_call_id_get_call_id(BELLE_SIP_HEADER_CALL_ID(belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request), belle_sip_header_call_id_t))));
	}

	return result;

}

int SalOp::send_request(belle_sip_request_t* request) {
	bool_t need_contact=FALSE;
	if (request==NULL) {
		return -1; /*sanity check*/
	}
	/*
	  Header field          where   proxy ACK BYE CAN INV OPT REG
	  ___________________________________________________________
	  Contact                 R            o   -   -   m   o   o
	 */
	if (strcmp(belle_sip_request_get_method(request),"INVITE")==0
			||strcmp(belle_sip_request_get_method(request),"REGISTER")==0
			||strcmp(belle_sip_request_get_method(request),"SUBSCRIBE")==0
			||strcmp(belle_sip_request_get_method(request),"OPTIONS")==0
			||strcmp(belle_sip_request_get_method(request),"REFER")==0) /* Despite contact seems not mandatory, call flow example show a Contact in REFER requests*/
		need_contact=TRUE;

	return send_request_with_contact(request,need_contact);
}

void SalOp::resend_request(belle_sip_request_t* request) {
	belle_sip_header_cseq_t* cseq=(belle_sip_header_cseq_t*)belle_sip_message_get_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_CSEQ);
	belle_sip_header_cseq_set_seq_number(cseq,belle_sip_header_cseq_get_seq_number(cseq)+1);
	send_request(request);
}

void SalOp::process_authentication() {
	belle_sip_request_t* initial_request=belle_sip_transaction_get_request((belle_sip_transaction_t*)this->pending_auth_transaction);
	belle_sip_request_t* new_request;
	bool_t is_within_dialog=FALSE;
	belle_sip_list_t* auth_list=NULL;
	belle_sip_auth_event_t* auth_event;
	belle_sip_response_t *response=belle_sip_transaction_get_response((belle_sip_transaction_t*)this->pending_auth_transaction);
	belle_sip_header_from_t *from=belle_sip_message_get_header_by_type(initial_request,belle_sip_header_from_t);
	belle_sip_uri_t *from_uri=belle_sip_header_address_get_uri((belle_sip_header_address_t*)from);

	if (strcasecmp(belle_sip_uri_get_host(from_uri),"anonymous.invalid")==0){
		/*prefer using the from from the SalOp*/
		from_uri=belle_sip_header_address_get_uri((belle_sip_header_address_t*)get_from_address());
	}

	if (this->dialog && belle_sip_dialog_get_state(this->dialog)==BELLE_SIP_DIALOG_CONFIRMED) {
		new_request = belle_sip_dialog_create_request_from(this->dialog,initial_request);
		if (!new_request)
			new_request = belle_sip_dialog_create_queued_request_from(this->dialog,initial_request);
		is_within_dialog=TRUE;
	} else {
		new_request=initial_request;
		belle_sip_message_remove_header(BELLE_SIP_MESSAGE(new_request),BELLE_SIP_AUTHORIZATION);
		belle_sip_message_remove_header(BELLE_SIP_MESSAGE(new_request),BELLE_SIP_PROXY_AUTHORIZATION);
	}
	if (new_request==NULL) {
		ms_error("sal_process_authentication() op=[%p] cannot obtain new request from dialog.",this);
		return;
	}

	if (belle_sip_provider_add_authorization(this->root->prov,new_request,response,from_uri,&auth_list,this->realm)) {
		if (is_within_dialog) {
			send_request(new_request);
		} else {
			resend_request(new_request);
		}
		this->root->remove_pending_auth(this);
	}else {
		belle_sip_header_from_t *from=belle_sip_message_get_header_by_type(response,belle_sip_header_from_t);
		char *tmp=belle_sip_object_to_string(belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(from)));
		ms_message("No auth info found for [%s]",tmp);
		belle_sip_free(tmp);
		this->root->add_pending_auth(this);

		if (is_within_dialog) {
			belle_sip_object_unref(new_request);
		}
	}
	/*always store auth info, for case of wrong credential*/
	if (this->auth_info) {
		sal_auth_info_delete(this->auth_info);
		this->auth_info=NULL;
	}
	if (auth_list){
		auth_event=(belle_sip_auth_event_t*)(auth_list->data);
		this->auth_info=sal_auth_info_create(auth_event);
		belle_sip_list_free_with_data(auth_list,(void (*)(void*))belle_sip_auth_event_destroy);
	}
}

void SalOp::authenticate(const SalAuthInfo *info) {
	if (this->type == Type::Register) {
		/*Registration authenticate is just about registering again*/
		register_refresh(-1);
	}else {
		/*for sure auth info will be accessible from the provider*/
		process_authentication();
	}
	return ;
}

char *SalOp::get_dialog_id() const {
	if (this->dialog != NULL) {
		return ms_strdup_printf("%s;to-tag=%s;from-tag=%s", this->call_id,
			belle_sip_dialog_get_remote_tag(this->dialog), belle_sip_dialog_get_local_tag(this->dialog));
	}
	return NULL;
}

int SalOp::get_address_family() const {
	belle_sip_transaction_t *tr=NULL;
	belle_sip_header_address_t *contact;
	

	if (this->refresher)
		tr=(belle_sip_transaction_t *)belle_sip_refresher_get_transaction(this->refresher);

	if (tr==NULL)
		tr=(belle_sip_transaction_t *)this->pending_client_trans;
	if (tr==NULL)
		tr=(belle_sip_transaction_t *)this->pending_server_trans;
	
	if (tr==NULL){
		ms_error("Unable to determine IP version from signaling operation.");
		return AF_UNSPEC;
	}
	
	
	if (this->refresher) {
		belle_sip_response_t *resp = belle_sip_transaction_get_response(tr);
		belle_sip_header_via_t *via = resp ?belle_sip_message_get_header_by_type(resp,belle_sip_header_via_t):NULL;
		if (!via){
			ms_error("Unable to determine IP version from signaling operation, no via header found.");
			return AF_UNSPEC;
		}
		return (strchr(belle_sip_header_via_get_host(via),':') != NULL) ? AF_INET6 : AF_INET;
	} else {
		belle_sip_request_t *req = belle_sip_transaction_get_request(tr);
		contact=(belle_sip_header_address_t*)belle_sip_message_get_header_by_type(req,belle_sip_header_contact_t);
		if (!contact){
			ms_error("Unable to determine IP version from signaling operation, no contact header found.");
		}
		return sal_address_is_ipv6((SalAddress*)contact) ? AF_INET6 : AF_INET;
	}
}

bool_t SalOp::is_idle() const {
	if (this->dialog){
		return !belle_sip_dialog_request_pending(this->dialog);
	}
	return TRUE;
}

void SalOp::set_entity_tag(const char* entity_tag) {
	if (this->entity_tag != NULL) ms_free(this->entity_tag);
	this->entity_tag = entity_tag ? ms_strdup(entity_tag) : NULL;
}

void SalOp::set_event(const char *eventname) {
	belle_sip_header_event_t *header = NULL;
	if (this->event) belle_sip_object_unref(this->event);
	if (eventname){
		header = belle_sip_header_event_create(eventname);
		belle_sip_object_ref(header);
	}
	this->event = header;
}

void SalOp::add_initial_route_set(belle_sip_request_t *request, const MSList *list) {
	const MSList *elem;
	for (elem=list;elem!=NULL;elem=elem->next){
		SalAddress *addr=(SalAddress*)elem->data;
		belle_sip_header_route_t *route;
		belle_sip_uri_t *uri;
		/*Optimization: if the initial route set only contains one URI which is the same as the request URI, ommit it*/
		if (elem==list && list->next==NULL){
			belle_sip_uri_t *requri=belle_sip_request_get_uri(request);
			/*skip the first route it is the same as the request uri*/
			if (strcmp(sal_address_get_domain(addr),belle_sip_uri_get_host(requri))==0 ){
				ms_message("Skipping top route of initial route-set because same as request-uri.");
				continue;
			}
		}

		route=belle_sip_header_route_create((belle_sip_header_address_t*)addr);
		uri=belle_sip_header_address_get_uri((belle_sip_header_address_t*)route);
		belle_sip_uri_set_lr_param(uri,1);
		belle_sip_message_add_header((belle_sip_message_t*)request,(belle_sip_header_t*)route);
	}
}

belle_sip_request_t* SalOp::build_request(const char* method) {
	belle_sip_header_from_t* from_header;
	belle_sip_header_to_t* to_header;
	belle_sip_provider_t* prov=this->root->prov;
	belle_sip_request_t *req;
	belle_sip_uri_t* req_uri;
	belle_sip_uri_t* to_uri;
	belle_sip_header_call_id_t *call_id_header;

	const SalAddress* to_address;
	const MSList *elem=get_route_addresses();
	char token[10];

	/* check that the op has a correct to address */
	to_address = get_to_address();
	if( to_address == NULL ){
		ms_error("No To: address, cannot build request");
		return NULL;
	}

	to_uri = belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(to_address));
	if( to_uri == NULL ){
		ms_error("To: address is invalid, cannot build request");
		return NULL;
	}

	if (strcmp("REGISTER",method)==0 || this->privacy==SalPrivacyNone) {
		from_header = belle_sip_header_from_create(BELLE_SIP_HEADER_ADDRESS(get_from_address())
						,belle_sip_random_token(token,sizeof(token)));
	} else {
		from_header=belle_sip_header_from_create2("Anonymous <sip:anonymous@anonymous.invalid>",belle_sip_random_token(token,sizeof(token)));
	}
	/*make sure to preserve components like headers or port*/

	req_uri = (belle_sip_uri_t*)belle_sip_object_clone((belle_sip_object_t*)to_uri);
	belle_sip_uri_set_secure(req_uri,sal_op_is_secure(this));

	to_header = belle_sip_header_to_create(BELLE_SIP_HEADER_ADDRESS(to_address),NULL);
	call_id_header = belle_sip_provider_create_call_id(prov);
	if (get_call_id()) {
		belle_sip_header_call_id_set_call_id(call_id_header, get_call_id());
	}

	req=belle_sip_request_create(
					req_uri,
					method,
					call_id_header,
					belle_sip_header_cseq_create(20,method),
					from_header,
					to_header,
					belle_sip_header_via_new(),
					70);

	if (this->privacy & SalPrivacyId) {
		belle_sip_header_p_preferred_identity_t* p_preferred_identity=belle_sip_header_p_preferred_identity_create(BELLE_SIP_HEADER_ADDRESS(get_from_address()));
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(p_preferred_identity));
	}

	if (elem && strcmp(method,"REGISTER")!=0 && !this->root->no_initial_route){
		add_initial_route_set(req,elem);
	}

	if (strcmp("REGISTER",method)!=0 && this->privacy!=SalPrivacyNone ){
		belle_sip_header_privacy_t* privacy_header=belle_sip_header_privacy_new();
		if (this->privacy&SalPrivacyCritical)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacyCritical));
		if (this->privacy&SalPrivacyHeader)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacyHeader));
		if (this->privacy&SalPrivacyId)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacyId));
		if (this->privacy&SalPrivacyNone)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacyNone));
		if (this->privacy&SalPrivacySession)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacySession));
		if (this->privacy&SalPrivacyUser)
			belle_sip_header_privacy_add_privacy(privacy_header,sal_privacy_to_string(SalPrivacyUser));
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),BELLE_SIP_HEADER(privacy_header));
	}
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(req),this->root->supported);
	return req;
}

void SalOp::set_error_info_from_response(belle_sip_response_t *response) {
	int code = belle_sip_response_get_status_code(response);
	const char *reason_phrase=belle_sip_response_get_reason_phrase(response);
	belle_sip_header_t *warning=belle_sip_message_get_header(BELLE_SIP_MESSAGE(response),"Warning");
	SalErrorInfo *ei=&this->error_info;
	const char *warnings;

	warnings=warning ? belle_sip_header_get_unparsed_value(warning) : NULL;
	sal_error_info_set(ei,SalReasonUnknown,"SIP", code,reason_phrase,warnings);
	set_reason_error_info(BELLE_SIP_MESSAGE(response));
}

const char* SalOp::to_string(const State value) {
	switch(value) {
		case State::Early: return"SalOpStateEarly";
		case State::Active: return "SalOpStateActive";
		case State::Terminating: return "SalOpStateTerminating";
		case State::Terminated: return "SalOpStateTerminated";
	default:
		return "Unknown";
	}
}

void SalOp::set_reason_error_info(belle_sip_message_t *msg) {
	belle_sip_header_reason_t* reason_header = belle_sip_message_get_header_by_type(msg,belle_sip_header_reason_t);
	if (reason_header){
		SalErrorInfo *ei=&this->reason_error_info; // ?//
		const char *protocol = belle_sip_header_reason_get_protocol(reason_header);
		int code = belle_sip_header_reason_get_cause(reason_header);
		const char *text = belle_sip_header_reason_get_text(reason_header);
		sal_error_info_set(ei, SalReasonUnknown, protocol, code, text, NULL);
	}
}

void SalOp::set_referred_by(belle_sip_header_referred_by_t* referred_by) {
	if (this->referred_by){
		belle_sip_object_unref(this->referred_by);
	}
	
	this->referred_by=referred_by;
	belle_sip_object_ref(this->referred_by);
}

void SalOp::set_replaces(belle_sip_header_replaces_t* replaces) {
	if (this->replaces){
		belle_sip_object_unref(this->replaces);
	}
	
	this->replaces=replaces;
	belle_sip_object_ref(this->replaces);
}

int SalOp::send_request_with_expires(belle_sip_request_t* request,int expires) {
	belle_sip_header_expires_t* expires_header=(belle_sip_header_expires_t*)belle_sip_message_get_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_EXPIRES);

	if (!expires_header && expires>=0) {
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(request),BELLE_SIP_HEADER(expires_header=belle_sip_header_expires_new()));
	}
	if (expires_header) belle_sip_header_expires_set_expires(expires_header,expires);
	return send_request(request);
}

int SalOp::send_and_create_refresher(belle_sip_request_t* req, int expires,belle_sip_refresher_listener_t listener) {
	if (send_request_with_expires(req,expires)==0) {
		if (this->refresher) {
			belle_sip_refresher_stop(this->refresher);
			belle_sip_object_unref(this->refresher);
		}
		if ((this->refresher = belle_sip_client_transaction_create_refresher(this->pending_client_trans))) {
			/*since refresher acquires the transaction, we should remove our context from the transaction, because we won't be notified
			 * that it is terminated anymore.*/
			unref();/*loose the reference that was given to the transaction when creating it*/
			/* Note that the refresher will replace our data with belle_sip_transaction_set_application_data().
			 Something in the design is not very good here, it makes things complicated to the belle-sip user.
			 Possible ideas to improve things: refresher shall not use belle_sip_transaction_set_application_data() internally, refresher should let the first transaction
			 notify the user as a normal transaction*/
			belle_sip_refresher_set_listener(this->refresher,listener, this);
			belle_sip_refresher_set_retry_after(this->refresher,this->root->refresher_retry_after);
			belle_sip_refresher_set_realm(this->refresher,this->realm);
			belle_sip_refresher_enable_manual_mode(this->refresher, this->manual_refresher);
			return 0;
		} else {
			return -1;
		}
	}
	return -1;
}

belle_sip_header_contact_t *SalOp::create_contact() {
	belle_sip_header_contact_t* contact_header;
	belle_sip_uri_t* contact_uri;

	if (get_contact_address()) {
		contact_header = belle_sip_header_contact_create(BELLE_SIP_HEADER_ADDRESS(get_contact_address()));
	} else {
		contact_header= belle_sip_header_contact_new();
	}

	if (!(contact_uri=belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(contact_header)))) {
		/*no uri, just creating a new one*/
		contact_uri=belle_sip_uri_new();
		belle_sip_header_address_set_uri(BELLE_SIP_HEADER_ADDRESS(contact_header),contact_uri);
	}

	belle_sip_uri_set_user_password(contact_uri,NULL);
	belle_sip_uri_set_secure(contact_uri,sal_op_is_secure(this));
	if (this->privacy!=SalPrivacyNone){
		belle_sip_uri_set_user(contact_uri,NULL);
	}
	belle_sip_header_contact_set_automatic(contact_header,this->root->auto_contacts);
	if (this->root->uuid){
		if (belle_sip_parameters_has_parameter(BELLE_SIP_PARAMETERS(contact_header),"+sip.instance")==0){
			char *instance_id=belle_sip_strdup_printf("\"<urn:uuid:%s>\"",this->root->uuid);
			belle_sip_parameters_set_parameter(BELLE_SIP_PARAMETERS(contact_header),"+sip.instance",instance_id);
			belle_sip_free(instance_id);
		}
	}
	return contact_header;
}

void SalOp::unlink_op_with_dialog(belle_sip_dialog_t* dialog) {
	belle_sip_dialog_set_application_data(dialog,NULL);
	unref();
	belle_sip_object_unref(dialog);
}

belle_sip_dialog_t *SalOp::link_op_with_dialog(belle_sip_dialog_t* dialog) {
	belle_sip_dialog_set_application_data(dialog,ref());
	belle_sip_object_ref(dialog);
	return dialog;
}

void SalOp::set_or_update_dialog(belle_sip_dialog_t* dialog) {
	ms_message("op [%p] : set_or_update_dialog() current=[%p] new=[%p]", this, this->dialog,dialog);
	ref();
	if (this->dialog!=dialog){
		if (this->dialog){
			/*FIXME: shouldn't we delete unconfirmed dialogs ?*/
			unlink_op_with_dialog(this->dialog);
			this->dialog=NULL;
		}
		if (dialog) {
			this->dialog=link_op_with_dialog(dialog);
			belle_sip_dialog_enable_pending_trans_checking(dialog,this->root->pending_trans_checking);
		}
	}
	unref();
}

int SalOp::ping(const char *from, const char *to) {
	set_from(from);
	set_to(to);
	return send_request(build_request("OPTIONS"));
}

int SalOp::send_info(const char *from, const char *to, const SalBodyHandler *body_handler) {
	if (this->dialog && belle_sip_dialog_get_state(this->dialog) == BELLE_SIP_DIALOG_CONFIRMED) {
		belle_sip_request_t *req;
		belle_sip_dialog_enable_pending_trans_checking(this->dialog,this->root->pending_trans_checking);
		req=belle_sip_dialog_create_queued_request(this->dialog,"INFO");
		belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(req), BELLE_SIP_BODY_HANDLER(body_handler));
		return send_request(req);
	}else{
		ms_error("Cannot send INFO message on op [%p] because dialog is not in confirmed state yet.", this);
	}
	return -1;
}

SalBodyHandler *SalOp::get_body_handler(belle_sip_message_t *msg) {
	belle_sip_body_handler_t *body_handler = belle_sip_message_get_body_handler(msg);
	if (body_handler != NULL) {
		belle_sip_header_content_type_t *content_type = belle_sip_message_get_header_by_type(msg, belle_sip_header_content_type_t);
		belle_sip_header_content_length_t *content_length = belle_sip_message_get_header_by_type(msg, belle_sip_header_content_length_t);
		belle_sip_header_t *content_encoding = belle_sip_message_get_header(msg, "Content-Encoding");
		if (content_type != NULL) belle_sip_body_handler_add_header(body_handler, BELLE_SIP_HEADER(content_type));
		if (content_length != NULL) belle_sip_body_handler_add_header(body_handler, BELLE_SIP_HEADER(content_length));
		if (content_encoding != NULL) belle_sip_body_handler_add_header(body_handler, content_encoding);
	}
	return (SalBodyHandler *)body_handler;
}

void SalOp::assign_recv_headers(belle_sip_message_t *incoming) {
	if (incoming) belle_sip_object_ref(incoming);
	if (this->recv_custom_headers){
		belle_sip_object_unref(this->recv_custom_headers);
		this->recv_custom_headers=NULL;
	}
	if (incoming){
		this->recv_custom_headers=(SalCustomHeader*)incoming;
	}
}

int to_sip_code(SalReason r) {
	int ret=500;
	switch(r){
		case SalReasonNone:
			ret=200;
			break;
		case SalReasonIOError:
			ret=503;
			break;
		case SalReasonUnknown:
			ret=400;
			break;
		case SalReasonBusy:
			ret=486;
			break;
		case SalReasonDeclined:
			ret=603;
			break;
		case SalReasonDoNotDisturb:
			ret=600;
			break;
		case SalReasonForbidden:
			ret=403;
			break;
		case SalReasonUnsupportedContent:
			ret=415;
			break;
		case SalReasonNotFound:
			ret=404;
			break;
		case SalReasonRedirect:
			ret=302;
			break;
		case SalReasonTemporarilyUnavailable:
			ret=480;
			break;
		case SalReasonServiceUnavailable:
			ret=503;
			break;
		case SalReasonRequestPending:
			ret=491;
			break;
		case SalReasonUnauthorized:
			ret=401;
			break;
		case SalReasonNotAcceptable:
			ret=488; /*or maybe 606 Not Acceptable ?*/
			break;
		case SalReasonNoMatch:
			ret=481;
			break;
		case SalReasonRequestTimeout:
			ret=408;
			break;
		case SalReasonMovedPermanently:
			ret=301;
			break;
		case SalReasonGone:
			ret=410;
			break;
		case SalReasonAddressIncomplete:
			ret=484;
			break;
		case SalReasonNotImplemented:
			ret=501;
			break;
		case SalReasonServerTimeout:
			ret=504;
			break;
		case SalReasonBadGateway:
			ret=502;
			break;
		case SalReasonInternalError:
			ret=500;
			break;
	}
	return ret;
}
