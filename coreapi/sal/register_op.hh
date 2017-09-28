#ifndef _LINPHONE_SAL_REGISTER_OP_HH
#define _LINPHONE_SAL_REGISTER_OP_HH

#include "sal_op.hh"

class SalRegisterOp: public SalOp {
public:
    	SalRegisterOp(Sal *sal): SalOp(sal) {}
	int register_(const char *proxy, const char *from, int expires, const SalAddress* old_contact);
	int register_refresh(int expires) {return this->refresher ? belle_sip_refresher_refresh(this->refresher,expires) : -1;}
	int unregister() {return register_refresh(0);}
	
	virtual void authenticate(const SalAuthInfo *info) override {register_refresh(-1);}

private:
	virtual void fill_cbs() override {};
	static void register_refresher_listener(belle_sip_refresher_t* refresher, void* user_pointer, unsigned int status_code, const char* reason_phrase, int will_retry);
};

#endif // _LINPHONE_SAL_REGISTER_OP_HH
