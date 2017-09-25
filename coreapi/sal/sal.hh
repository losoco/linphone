#ifndef _LINPHONE_SAL_HH
#define _LINPHONE_SAL_HH

#include "sal/sal.h"

class SalOp;
class SalCall;
class MessageOp;
class SubscribeOp;

class Sal{
public:
	typedef void (*OnCallReceivedCb)(SalCall *op);
	typedef void (*OnCallRingingCb)(SalOp *op);
	typedef void (*OnCallAcceptedCb)(SalOp *op);
	typedef void (*OnCallAckReceivedCb)(SalOp *op, SalCustomHeader *ack);
	typedef void (*OnCallAckBeingSentCb)(SalOp *op, SalCustomHeader *ack);
	typedef void (*OnCallUpdatingCb)(SalOp *op, bool_t is_update);/* Called when a reINVITE/UPDATE is received*/
	typedef void (*OnCallTerminatedCb)(SalOp *op, const char *from);
	typedef void (*OnCallFailureCb)(SalOp *op);
	typedef void (*OnCallReleasedCb)(SalOp *salop);
	typedef void (*OnCallCancelDoneCb)(SalOp *salop);
	typedef void (*OnAuthRequestedLegacyCb)(SalOp *op, const char *realm, const char *username);
	typedef bool_t (*OnAuthRequestedCb)(Sal *sal,SalAuthInfo* info);
	typedef void (*OnAuthFailureCb)(SalOp *op, SalAuthInfo* info);
	typedef void (*OnRegisterSuccessCb)(SalOp *op, bool_t registered);
	typedef void (*OnRegisterFailureCb)(SalOp *op);
	typedef void (*OnVfuRequestCb)(SalOp *op);
	typedef void (*OnDtmfReceivedCb)(SalOp *op, char dtmf);
	typedef void (*OnReferCb)(Sal *sal, SalOp *op, const char *referto);
	typedef void (*OnMessageReceivedCb)(SalOp *op, const SalMessage *msg);
	typedef void (*OnMessageDeliveryUpdateCb)(SalOp *op, SalMessageDeliveryStatus);
	typedef void (*OnNotifyReferCb)(SalOp *op, SalReferStatus state);
	typedef void (*OnSubscribeResponseCb)(SalOp *op, SalSubscribeStatus status, int will_retry);
	typedef void (*OnNotifyCb)(SubscribeOp *op, SalSubscribeStatus status, const char *event, SalBodyHandler *body);
	typedef void (*OnSubscribeReceivedCb)(SubscribeOp *salop, const char *event, const SalBodyHandler *body);
	typedef void (*OnIncomingSubscribeClosedCb)(SalOp *salop);
	typedef void (*OnParsePresenceRequestedCb)(SalOp *salop, const char *content_type, const char *content_subtype, const char *content, SalPresenceModel **result);
	typedef void (*OnConvertPresenceToXMLRequestedCb)(SalOp *salop, SalPresenceModel *presence, const char *contact, char **content);
	typedef void (*OnNotifyPresenceCb)(SalOp *op, SalSubscribeStatus ss, SalPresenceModel *model, const char *msg);
	typedef void (*OnSubscribePresenceReceivedCb)(SalOp *salop, const char *from);
	typedef void (*OnSubscribePresenceClosedCb)(SalOp *salop, const char *from);
	typedef void (*OnPingReplyCb)(SalOp *salop);
	typedef void (*OnInfoReceivedCb)(SalOp *salop, SalBodyHandler *body);
	typedef void (*OnPublishResponseCb)(SalOp *salop);
	typedef void (*OnNotifyResponseCb)(SalOp *salop);
	typedef void (*OnExpireCb)(SalOp *salop);
	
	struct Callbacks {
		OnCallReceivedCb call_received;
		OnCallReceivedCb call_rejected;
		OnCallRingingCb call_ringing;
		OnCallAcceptedCb call_accepted;
		OnCallAckReceivedCb call_ack_received;
		OnCallAckBeingSentCb call_ack_being_sent;
		OnCallUpdatingCb call_updating;
		OnCallTerminatedCb call_terminated;
		OnCallFailureCb call_failure;
		OnCallReleasedCb call_released;
		OnCallCancelDoneCb call_cancel_done;
		OnAuthFailureCb auth_failure;
		OnRegisterSuccessCb register_success;
		OnRegisterFailureCb register_failure;
		OnVfuRequestCb vfu_request;
		OnDtmfReceivedCb dtmf_received;
		OnReferCb refer_received;
		OnMessageReceivedCb message_received;
		OnMessageDeliveryUpdateCb message_delivery_update;
		OnNotifyReferCb notify_refer;
		OnSubscribeReceivedCb subscribe_received;
		OnIncomingSubscribeClosedCb incoming_subscribe_closed;
		OnSubscribeResponseCb subscribe_response;
		OnNotifyCb notify;
		OnSubscribePresenceReceivedCb subscribe_presence_received;
		OnSubscribePresenceClosedCb subscribe_presence_closed;
		OnParsePresenceRequestedCb parse_presence_requested;
		OnConvertPresenceToXMLRequestedCb convert_presence_to_xml_requested;
		OnNotifyPresenceCb notify_presence;
		OnPingReplyCb ping_reply;
		OnAuthRequestedCb auth_requested;
		OnInfoReceivedCb info_received;
		OnPublishResponseCb on_publish_response;
		OnExpireCb on_expire;
		OnNotifyResponseCb on_notify_response;
	};
	
	Sal(MSFactory *factory);
	~Sal();
	void set_user_pointer(void *user_data) {this->up=user_data;}
	void *get_user_pointer() const {return this->up;}
	
	void set_callbacks(const Callbacks *cbs);
	int set_listen_port(const char *addr, int port, SalTransport tr, int is_tunneled);
	int get_listening_port(SalTransport tr);
	int unlisten_ports();
	int transport_available(SalTransport t);
	bool_t content_encoding_available(const char *content_encoding) {return (bool_t)belle_sip_stack_content_encoding_available(this->stack, content_encoding);}
	void set_dscp(int dscp) {belle_sip_stack_set_default_dscp(this->stack,dscp);}
	void set_supported_tags(const char* tags);
	void add_supported_tag(const char* tag);
	void remove_supported_tag(const char* tag);
	const char *get_supported_tags() const {return this->supported ? belle_sip_header_get_unparsed_value(this->supported) : NULL;}
	int reset_transports();
	ortp_socket_t get_socket() const;
	void set_user_agent(const char *user_agent);
	const char* get_user_agent() const;
	void append_stack_string_to_user_agent();
	void set_keepalive_period(unsigned int value);
	void use_tcp_tls_keepalive(bool_t enabled) {this->use_tcp_tls_keep_alive=enabled;}
	int set_tunnel(void *tunnelclient);
	void enable_sip_update_method(bool_t value) {this->enable_sip_update=value;}
	bool_t is_content_type_supported(const char *content_type) const;
	void add_content_type_support(const char *content_type);
	unsigned int get_keepalive_period() const {return this->keep_alive;}
	void use_session_timers(int expires) {this->session_expires=expires;}
	void use_dates(bool_t enabled) {this->_use_dates=enabled;}
	void use_one_matching_codec_policy(bool_t one_matching_codec) {this->one_matching_codec=one_matching_codec;}
	void use_rport(bool_t use_rports);
	void enable_auto_contacts(bool_t enabled) {this->auto_contacts=enabled;}
	void set_root_ca(const char* rootCa);
	void set_root_ca_data(const char* data);
	const char *get_root_ca() const {return this->root_ca;}
	void verify_server_certificates(bool_t verify);
	void verify_server_cn(bool_t verify);
	void set_ssl_config(void *ssl_config);
	void set_uuid(const char *uuid);
	int create_uuid(char *uuid, size_t len);
	static int generate_uuid(char *uuid, size_t len);
	void enable_test_features(bool_t enabled) {this->_enable_test_features=enabled;}
	void use_no_initial_route(bool_t enabled) {this->no_initial_route=enabled;}
	int iterate() {belle_sip_stack_sleep(this->stack,0); return 0;}
	bctbx_list_t *get_pending_auths() const {return bctbx_list_copy(this->pending_auths);}
	void set_default_sdp_handling(SalOpSDPHandling sdp_handling_method);
	void enable_nat_helper(bool_t enable);
	void get_default_local_ip(int address_family, char *ip, size_t iplen);
	belle_sip_resolver_context_t *resolve_a(const char *name, int port, int family, belle_sip_resolver_callback_t cb, void *data)
		{return belle_sip_stack_resolve_a(this->stack,name,port,family,cb,data);}
	belle_sip_resolver_context_t *resolve(const char *service, const char *transport, const char *name, int port, int family, belle_sip_resolver_callback_t cb, void *data)
		{return belle_sip_stack_resolve(this->stack, service, transport, name, port, family, cb, data);}
	void  set_send_error(int value) {belle_sip_stack_set_send_error(this->stack,value);}
	void  set_recv_error(int value) {belle_sip_provider_set_recv_error(this->prov,value);}
	void enable_unconditional_answer(int value) {belle_sip_provider_enable_unconditional_answer(this->prov,value);}
	bool_t pending_trans_checking_enabled() const {return this->pending_trans_checking;}
	int enable_pending_trans_checking(bool_t value) {this->pending_trans_checking = value; return 0;}
	void set_refresher_retry_after(int value) {this->refresher_retry_after=value;}
	int get_refresher_retry_after() const {return this->refresher_retry_after;}
	bool_t nat_helper_enabled() const {return this->_nat_helper_enabled;}
	void set_dns_timeout(int timeout) {belle_sip_stack_set_dns_timeout(this->stack, timeout);}
	int get_dns_timeout() const {return belle_sip_stack_get_dns_timeout(this->stack);}
	void set_transport_timeout(int timeout) {belle_sip_stack_set_transport_timeout(this->stack, timeout);}
	int get_transport_timeout() const {return belle_sip_stack_get_transport_timeout(this->stack);}
	void set_dns_servers(const bctbx_list_t *servers);
	void enable_dns_srv(bool_t enable) {belle_sip_stack_enable_dns_srv(this->stack, (unsigned char)enable);}
	bool_t dns_srv_enabled() const {return (bool_t)belle_sip_stack_dns_srv_enabled(this->stack);}
	void enable_dns_search(bool_t enable) {belle_sip_stack_enable_dns_search(this->stack, (unsigned char)enable);}
	bool_t dns_search_enabled() const {return (bool_t)belle_sip_stack_dns_search_enabled(this->stack);}
	void set_dns_user_hosts_file(const char *hosts_file) {belle_sip_stack_set_dns_user_hosts_file(this->stack, hosts_file);}
	const char *get_dns_user_hosts_file() const {return belle_sip_stack_get_dns_user_hosts_file(this->stack);}
	belle_sip_source_t *create_timer(belle_sip_source_func_t func, void *data, unsigned int timeout_value_ms, const char* timer_name);
	void cancel_timer(belle_sip_source_t *timer);
	void *get_stack_impl() {return this->stack;}
	void set_http_proxy_host(const char *host) {belle_sip_stack_set_http_proxy_host(this->stack, host);}
	void set_http_proxy_port(int port) {belle_sip_stack_set_http_proxy_port(this->stack, port);}
	const char *get_http_proxy_host() const {return belle_sip_stack_get_http_proxy_host(this->stack);}
	int get_http_proxy_port() const {return belle_sip_stack_get_http_proxy_port(this->stack);}
	
private:
	struct sal_uuid_t {
		unsigned int time_low;
		unsigned short time_mid;
		unsigned short time_hi_and_version;
		unsigned char clock_seq_hi_and_reserved;
		unsigned char clock_seq_low;
		unsigned char node[6];
	};
	
	void set_tls_properties();
	int add_listen_port(SalAddress* addr, bool_t is_tunneled);
	void make_supported_header();
	void add_pending_auth(SalOp *op);
	void remove_pending_auth(SalOp *op);
	belle_sip_response_t* create_response_from_request (belle_sip_request_t* req, int code );
	
	static void unimplemented_stub() {ms_warning("Unimplemented SAL callback");}
	static void remove_listening_point(belle_sip_listening_point_t* lp,belle_sip_provider_t* prov) {belle_sip_provider_remove_listening_point(prov,lp);}
	
	static void process_dialog_terminated_cb(void *sal, const belle_sip_dialog_terminated_event_t *event);
	static void process_io_error_cb(void *user_ctx, const belle_sip_io_error_event_t *event);
	static void process_request_event_cb(void *ud, const belle_sip_request_event_t *event);
	static void process_response_event_cb(void *user_ctx, const belle_sip_response_event_t *event);
	static void process_timeout_cb(void *user_ctx, const belle_sip_timeout_event_t *event);
	static void process_transaction_terminated_cb(void *user_ctx, const belle_sip_transaction_terminated_event_t *event);
	static void process_auth_requested_cb(void *sal, belle_sip_auth_event_t *event);
	
	MSFactory *factory = NULL;
	Callbacks callbacks = {0};
	MSList *pending_auths = NULL;/*MSList of SalOp */
	belle_sip_stack_t* stack = NULL;
	belle_sip_provider_t *prov = NULL;
	belle_sip_header_user_agent_t* user_agent = NULL;
	belle_sip_listener_t *listener = NULL;
	void *tunnel_client = NULL;
	void *up = NULL; /*user pointer*/
	int session_expires = 0;
	unsigned int keep_alive = 0;
	char *root_ca = NULL;
	char *root_ca_data = NULL;
	char *uuid = NULL;
	int refresher_retry_after = 60000; /*retry after value for refresher*/
	MSList *supported_tags = NULL;/*list of char * */
	belle_sip_header_t *supported = NULL;
	bool_t one_matching_codec = FALSE;
	bool_t use_tcp_tls_keep_alive = FALSE;
	bool_t _nat_helper_enabled = FALSE;
	bool_t tls_verify = TRUE;
	bool_t tls_verify_cn = TRUE;
	bool_t _use_dates = FALSE;
	bool_t auto_contacts = TRUE;
	bool_t _enable_test_features = FALSE;
	bool_t no_initial_route = FALSE;
	bool_t enable_sip_update = TRUE; /*true by default*/
	SalOpSDPHandling default_sdp_handling = SalOpSDPNormal;
	bool_t pending_trans_checking = TRUE; /*testing purpose*/
	void *ssl_config = NULL;
	bctbx_list_t *supported_content_types = NULL; /* list of char* */
	
	friend class SalOp;
	friend class SalCall;
	friend class RegisterOp;
	friend class MessageOp;
	friend class PresenceOp;
	friend class SubscribeOp;
	friend class PublishOp;
};

class SalOp {
public:
	SalOp(Sal *sal);
	virtual ~SalOp();
	SalOp *ref();
	void *unref();
	void set_user_pointer(void *up) {this->user_pointer=up;}
	void *get_user_pointer() const {return this->user_pointer;}
	
	void set_contact_address(const SalAddress* address);
	void set_and_clean_contact_address(SalAddress* address);
	void set_route(const char *route);
	void set_route_address(const SalAddress* address);
	void add_route_address(const SalAddress* address);
	void set_realm(const char *realm);
	void set_from(const char *from);
	void set_from_address(const SalAddress *from);
	void set_to(const char *to);
	void set_to_address(const SalAddress *to);
	void set_diversion_address(const SalAddress *diversion);
	void set_service_route(const SalAddress* service_route);
	void set_manual_refresher_mode(bool_t enabled) {this->manual_refresher=enabled;}
	void set_entity_tag(const char* entity_tag);
	void set_event(const char *eventname);
	void set_privacy(SalPrivacyMask privacy) {this->privacy=privacy;}
	void set_sent_custom_header(SalCustomHeader* ch);
	
	const char *get_from() const {return this->from;}
	const SalAddress *get_from_address() const {return this->from_address;}
	const char *get_to() const {return this->to;}
	const SalAddress *get_to_address() const {return this->to_address;}
	const SalAddress *get_diversion_address() const {return this->diversion_address;}
	const SalAddress *get_contact_address() const {return this->contact_address;}
	const bctbx_list_t *get_route_addresses() const {return this->route_addresses;}
	const char *get_proxy() const {return this->route;}
	const char *get_remote_contact() const {return this->remote_contact;}
	const SalAddress *get_remote_contact_address() const {return this->remote_contact_address;}
	const char *get_network_origin() const {return this->origin;}
	const char *get_remote_ua() const {return this->remote_ua;}
	const char* get_call_id() const {return  this->call_id;}
	char* get_dialog_id() const;
	const SalAddress *get_service_route() const {return this->service_route;}
	int get_address_family() const;
	const char *get_entity_tag() const {return this->entity_tag;}
	SalPrivacyMask get_privacy() const {return this->privacy;}
	const SalErrorInfo *get_error_info() const {return &this->error_info;}
	const SalErrorInfo *get_reason_error_info() const {return &this->reason_error_info;}
	const SalCustomHeader *get_recv_custom_header() const {return this->recv_custom_headers;}
	Sal *get_sal() const {return this->root;}
	
	bool_t is_forked_of(const SalOp *op2) const {return this->call_id && op2->call_id && strcmp(this->call_id, op2->call_id) == 0;}
	bool_t is_idle() const ;
	
	void stop_refreshing() {if (this->refresher) belle_sip_refresher_stop(this->refresher);}
	int refresh();
	void kill_dialog();
	void release();
	
	virtual void authenticate(const SalAuthInfo *info) {process_authentication();}
	void cancel_authentication() {ms_fatal("sal_op_cancel_authentication not implemented yet");}
	SalAuthInfo *get_auth_requested() {return this->auth_info;}
	
	int ping(const char *from, const char *to);
	int send_info(const char *from, const char *to, const SalBodyHandler *body_handler);
	
	const char *get_public_address(int *port) {return this->refresher ? belle_sip_refresher_get_public_address(this->refresher, port) : NULL;}
	const char *get_local_address(int *port) {return this->refresher ? belle_sip_refresher_get_local_address(this->refresher, port) : NULL;}
	
	void enable_cnx_ip_to_0000_if_sendonly(bool_t yesno) {this->_cnx_ip_to_0000_if_sendonly_enabled = yesno;}
	bool_t cnx_ip_to_0000_if_sendonly_enabled() const {return this->_cnx_ip_to_0000_if_sendonly_enabled;}
	
protected:
	enum class State {
		Early = 0,
		Active,
		Terminating, /*this state is used to wait until a proceeding state, so we can send the cancel*/
		Terminated
	};
	
	static const char* to_string(const State value);

	enum class Dir {
		Incoming = 0,
		Outgoing
	};
	
	enum class Type {
		Unknown,
		Register,
		Call,
		Message,
		Presence,
		Publish,
		Subscribe
	};
	
	static const char *to_string(const SalOp::Type type);
	
	typedef void (*ReleaseCb)(SalOp *op);
	
	virtual void fill_cbs() {};
	void release_impl();
	void process_authentication();
	
	belle_sip_request_t* build_request(const char* method);
	int send_request(belle_sip_request_t* request);
	int send_request_with_contact(belle_sip_request_t* request, bool_t add_contact);
	int send_request_with_expires(belle_sip_request_t* request,int expires);
	void resend_request(belle_sip_request_t* request);
	int send_and_create_refresher(belle_sip_request_t* req, int expires,belle_sip_refresher_listener_t listener);
	
	void set_reason_error_info(belle_sip_message_t *msg);
	void set_error_info_from_response(belle_sip_response_t *response);
	
	void set_referred_by(belle_sip_header_referred_by_t* referred_by);
	void set_replaces(belle_sip_header_replaces_t* replaces);
	
	void set_remote_contact(const char* remote_contact);
	void set_network_origin(const char *origin);
	void set_network_origin_address(SalAddress *origin);
	void set_privacy_from_message(belle_sip_message_t* msg);
	void set_remote_ua(belle_sip_message_t* message);
	
	belle_sip_response_t *create_response_from_request(belle_sip_request_t *req, int code) {return this->root->create_response_from_request(req,code);}
	belle_sip_header_contact_t *create_contact();
	
	void set_or_update_dialog(belle_sip_dialog_t* dialog);
	belle_sip_dialog_t *link_op_with_dialog(belle_sip_dialog_t* dialog);
	void unlink_op_with_dialog(belle_sip_dialog_t* dialog);
	
	SalBodyHandler *get_body_handler(belle_sip_message_t *msg);
	
	void assign_recv_headers(belle_sip_message_t *incoming);
	
	bool_t is_secure() const;
	void add_headers(belle_sip_header_t *h, belle_sip_message_t *msg);
	void add_custom_headers(belle_sip_message_t *msg);
    int unsubscribe();
	
	void process_incoming_message(const belle_sip_request_event_t *event);
	int reply_message(SalReason reason);
	void add_message_accept(belle_sip_message_t *msg);
	static bool_t is_external_body(belle_sip_header_content_type_t* content_type);
	
	static void assign_address(SalAddress** address, const char *value);
	static void assign_string(char **str, const char *arg);
	static void add_initial_route_set(belle_sip_request_t *request, const MSList *list);
	
	// SalOpBase
	Sal *root = NULL;
	char *route = NULL; /*or request-uri for REGISTER*/
	MSList* route_addresses = NULL; /*list of SalAddress* */
	SalAddress* contact_address = NULL;
	char *from = NULL;
	SalAddress* from_address = NULL;
	char *to = NULL;
	SalAddress* to_address = NULL;
	char *origin = NULL;
	SalAddress* origin_address = NULL;
	SalAddress* diversion_address = NULL;
	char *remote_ua = NULL;
	SalAddress* remote_contact_address = NULL;
	char *remote_contact = NULL;
	SalMediaDescription *local_media = NULL;
	SalMediaDescription *remote_media = NULL;
	SalCustomBody *custom_body = NULL;
	void *user_pointer = NULL;
	const char* call_id = NULL;
	char* realm = NULL;
	SalAddress* service_route = NULL; /*as defined by rfc3608, might be a list*/
	SalCustomHeader *sent_custom_headers = NULL;
	SalCustomHeader *recv_custom_headers = NULL;
	char* entity_tag = NULL; /*as defined by rfc3903 (I.E publih)*/
	ReleaseCb release_cb = NULL;
	
	// BelleSip implementation
	const belle_sip_listener_callbacks_t *callbacks = NULL;
	SalErrorInfo error_info;
	SalErrorInfo reason_error_info;
	belle_sip_client_transaction_t *pending_auth_transaction = NULL;
	belle_sip_server_transaction_t* pending_server_trans = NULL;
	belle_sip_server_transaction_t* pending_update_server_trans = NULL;
	belle_sip_client_transaction_t* pending_client_trans = NULL;
	SalAuthInfo* auth_info = NULL;
	belle_sip_dialog_t* dialog = NULL;
	belle_sip_header_replaces_t *replaces = NULL;
	belle_sip_header_referred_by_t *referred_by = NULL;
	SalMediaDescription *result = NULL;
	belle_sdp_session_description_t *sdp_answer = NULL;
	State state = State::Early;
	Dir dir = Dir::Incoming;
	belle_sip_refresher_t* refresher = NULL;
	int _ref = 0;
	Type type = Type::Unknown;
	SalPrivacyMask privacy = SalPrivacyNone;
	belle_sip_header_event_t *event = NULL; /*used by SalOpSubscribe kinds*/
	SalOpSDPHandling sdp_handling = SalOpSDPNormal;
	int auth_requests = 0; /*number of auth requested for this op*/
	bool_t _cnx_ip_to_0000_if_sendonly_enabled = FALSE;
	bool_t auto_answer_asked = FALSE;
	bool_t sdp_offering = FALSE;
	bool_t call_released = FALSE;
	bool_t manual_refresher = FALSE;
	bool_t has_auth_pending = FALSE;
	bool_t supports_session_timers = FALSE;
	bool_t op_released = FALSE;
	
	friend class Sal;
};

int to_sip_code(SalReason r);


#endif // _LINPHONE_SAL_HH
