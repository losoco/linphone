/*
 * call-session.h
 * Copyright (C) 2017  Belledonne Communications SARL
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CALL_SESSION_H_
#define _CALL_SESSION_H_

#include <memory>

#include "object/object.h"
#include "address/address.h"
#include "conference/conference.h"
#include "conference/params/call-session-params.h"
#include "conference/session/call-session-listener.h"
#include "sal/sal_call.hh"

// =============================================================================

LINPHONE_BEGIN_NAMESPACE

class CallPrivate;
class CallSessionPrivate;

class CallSession : public Object, public std::enable_shared_from_this<CallSession> {
	friend class CallPrivate;

public:
	CallSession (const Conference &conference, const std::shared_ptr<CallSessionParams> params, CallSessionListener *listener);

	LinphoneStatus accept (const std::shared_ptr<CallSessionParams> csp = nullptr);
	LinphoneStatus acceptUpdate (const std::shared_ptr<CallSessionParams> csp);
	virtual void configure (LinphoneCallDir direction, LinphoneProxyConfig *cfg, SalCall *op, const Address &from, const Address &to);
	LinphoneStatus decline (LinphoneReason reason);
	LinphoneStatus decline (const LinphoneErrorInfo *ei);
	virtual void initiateIncoming ();
	virtual bool initiateOutgoing ();
	virtual void iterate (time_t currentRealTime, bool oneSecondElapsed);
	virtual void startIncomingNotification ();
	virtual int startInvite (const Address *destination);
	LinphoneStatus terminate (const LinphoneErrorInfo *ei = nullptr);
	LinphoneStatus update (const std::shared_ptr<CallSessionParams> csp);

	std::shared_ptr<CallSessionParams> getCurrentParams ();
	LinphoneCallDir getDirection () const;
	int getDuration () const;
	const LinphoneErrorInfo * getErrorInfo () const;
	LinphoneCallLog * getLog () const;
	virtual const std::shared_ptr<CallSessionParams> getParams () const;
	LinphoneReason getReason () const;
	const Address& getRemoteAddress () const;
	std::string getRemoteAddressAsString () const;
	std::string getRemoteContact () const;
	const std::shared_ptr<CallSessionParams> getRemoteParams ();
	LinphoneCallState getState () const;

	std::string getRemoteUserAgent () const;

protected:
	explicit CallSession (CallSessionPrivate &p);

private:
	L_DECLARE_PRIVATE(CallSession);
	L_DISABLE_COPY(CallSession);
};

LINPHONE_END_NAMESPACE

#endif // ifndef _CALL_SESSION_H_
