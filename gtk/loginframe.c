/*
linphone, gtk-glade interface.
Copyright (C) 2009  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "linphone.h"

void linphone_gtk_login_frame_connect_clicked(GtkWidget *button);
void test_button_clicked_cb(GtkWidget *button);
void linphone_gtk_exit_login_frame(void);

enum {
	NetworkKindAdsl,
	NetworkKindOpticalFiber
};

static void do_login(SipSetupContext *ssctx, const char *identity, const char * passwd){
	if (sip_setup_context_login_account(ssctx,identity,passwd)==0){
	}
}

static gboolean do_login_noprompt(LinphoneProxyConfig *cfg){
	SipSetupContext *ssctx=linphone_proxy_config_get_sip_setup_context(cfg);
	LinphoneAddress *addr;
	const char *username;
	char *tmp;
	if (ssctx==NULL) return TRUE;/*not ready ?*/
	username=linphone_gtk_get_ui_config ("login_username",NULL);
	if (username==NULL) {
		linphone_gtk_set_ui_config_int("automatic_login",0);
		linphone_gtk_show_login_frame(cfg);
		return FALSE;
	}
	addr=linphone_address_new(linphone_proxy_config_get_identity(cfg));
	linphone_address_set_username(addr,username);
	tmp=linphone_address_as_string (addr);
	do_login(ssctx,tmp,NULL);
	linphone_address_destroy(addr);
	linphone_gtk_load_identities();
	return FALSE;
}

void linphone_gtk_show_login_frame(LinphoneProxyConfig *cfg){
	GtkWidget *mw=linphone_gtk_get_main_window();
	GtkWidget *label=linphone_gtk_get_widget(mw,"login_label");
	const LinphoneAuthInfo *ai;
	gchar *str;
	LinphoneAddress *from;
	LinphoneCore *lc=linphone_gtk_get_core();
	int nettype;
	const char *passwd=NULL;

	
	if (linphone_core_get_download_bandwidth(lc)==512 &&
		linphone_core_get_upload_bandwidth(lc)==512)
		nettype=NetworkKindOpticalFiber;
	else nettype=NetworkKindAdsl;
	gtk_combo_box_set_active(GTK_COMBO_BOX(linphone_gtk_get_widget(mw,"login_internet_kind")),nettype);
	//gtk_combo_box_set_active(GTK_COMBO_BOX(linphone_gtk_get_widget(mw,"internet_kind")),nettype);
	
	if (linphone_gtk_get_ui_config_int("automatic_login",0) ){
		g_timeout_add(250,(GSourceFunc)do_login_noprompt,cfg);
		return;
	}

	{
		const char *login_image=linphone_gtk_get_ui_config("login_image",NULL);
		if (login_image){
			GdkPixbuf *pbuf=create_pixbuf (login_image);
			gtk_image_set_from_pixbuf (GTK_IMAGE(linphone_gtk_get_widget(mw,"login_image")),
			                           pbuf);
			g_object_unref(G_OBJECT(pbuf));
		}
	}

	gtk_widget_hide(linphone_gtk_get_widget(mw,"disconnect_item"));
	gtk_widget_hide(linphone_gtk_get_widget(mw,"main_frame"));
	gtk_widget_show(linphone_gtk_get_widget(mw,"login_frame"));
	gtk_widget_set_sensitive(linphone_gtk_get_widget(mw,"options_menu"),FALSE);
	str=g_strdup_printf(_("Please enter login information for %s"),linphone_proxy_config_get_domain(cfg));
	gtk_label_set_text(GTK_LABEL(label),str);
	g_object_set_data(G_OBJECT(mw),"login_proxy_config",cfg);
	g_free(str);

	from=linphone_address_new(linphone_proxy_config_get_identity(cfg));
	if (linphone_address_get_username(from)[0]=='?'){
		const char *username=linphone_gtk_get_ui_config ("login_username",NULL);
		if (username)
			linphone_address_set_username(from,username);
	}
	
	ai=linphone_core_find_auth_info(lc,linphone_proxy_config_get_domain(cfg),linphone_address_get_username(from),NULL);
	/*display the last entered username, if not '?????'*/
	if (linphone_address_get_username(from)[0]!='?')
		gtk_entry_set_text(GTK_ENTRY(linphone_gtk_get_widget(mw,"login_username")),
			linphone_address_get_username(from));
	if (ai) passwd=linphone_auth_info_get_passwd(ai);
	gtk_entry_set_text(GTK_ENTRY(linphone_gtk_get_widget(mw,"login_password")),
		passwd!=NULL ? passwd : "");
	
	linphone_address_destroy(from);
}

void linphone_gtk_exit_login_frame(void){
	GtkWidget *mw=linphone_gtk_get_main_window();
	gtk_widget_show(linphone_gtk_get_widget(mw,"main_frame"));
	gtk_widget_hide(linphone_gtk_get_widget(mw,"login_frame"));
	gtk_widget_set_sensitive(linphone_gtk_get_widget(mw,"options_menu"),TRUE);
	gtk_widget_show(linphone_gtk_get_widget(mw,"disconnect_item"));
}

void linphone_gtk_logout_clicked(){
	LinphoneCore *lc=linphone_gtk_get_core();
	LinphoneProxyConfig *cfg=NULL;
	linphone_core_get_default_proxy(lc,&cfg);
	if (cfg){
		SipSetupContext *ss=linphone_proxy_config_get_sip_setup_context(cfg);
		if (ss){
			sip_setup_context_logout(ss);
			linphone_gtk_set_ui_config_int("automatic_login",FALSE);
			linphone_gtk_show_login_frame(cfg);
		}
	}
}



void linphone_gtk_login_frame_connect_clicked(GtkWidget *button){
	GtkWidget *mw=gtk_widget_get_toplevel(button);
	const char *username;
	const char *password;
	char *identity;
	gboolean autologin;
	LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)g_object_get_data(G_OBJECT(mw),"login_proxy_config");
	LinphoneAddress *from;
	SipSetupContext *ssctx=linphone_proxy_config_get_sip_setup_context(cfg);

	username=gtk_entry_get_text(GTK_ENTRY(linphone_gtk_get_widget(mw,"login_username")));
	password=gtk_entry_get_text(GTK_ENTRY(linphone_gtk_get_widget(mw,"login_password")));

	if (username==NULL || username[0]=='\0')
		return;

	autologin=gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(linphone_gtk_get_widget(mw,"automatic_login")));
	linphone_gtk_set_ui_config_int("automatic_login",autologin);
	linphone_gtk_set_ui_config("login_username",username);

	from=linphone_address_new(linphone_proxy_config_get_identity(cfg));
	linphone_address_set_username(from,username);
	identity=linphone_address_as_string(from);
	do_login(ssctx,identity,password);
	/*we need to refresh the identities since the proxy config may have changed.*/
	linphone_gtk_load_identities();
}

void test_cb( LinphoneContactSearch* req, MSList* friends, void* data )
{
	ms_message("LDAP Search CB received:");
	GtkEntry*    uribar = GTK_ENTRY(linphone_gtk_get_widget(linphone_gtk_get_main_window(),"uribar"));
	GtkTreeModel* model = gtk_entry_completion_get_model(gtk_entry_get_completion(uribar));
	GtkListStore*  list = GTK_LIST_STORE(model);
	GtkTreeIter iter;



	// clear completion list from previous LDAP completion suggestions
	if (!gtk_tree_model_get_iter_first(model,&iter)) return;
	do {
		int type;
		char* url;
		bool_t valid = TRUE;
		gtk_tree_model_get(model,&iter,1,&type,0,&url,-1);
		if (type == COMPLETION_LDAP) {
			ms_message("Removing entry for %s", url?url:"NULL");
			valid = gtk_list_store_remove(list, &iter);
		} else {
			ms_message("Keep entry for %s (type %d)", url?url:"NULL", type);
		}

		if( url ) g_free(url);
		if( !valid ) break;

	}while(gtk_tree_model_iter_next(model,&iter));

	while( friends ){
		LinphoneFriend* lf = friends->data;
		if( lf ) {
			const LinphoneAddress* la = linphone_friend_get_address(lf);
			if( la ){
				char *addr = linphone_address_as_string(la);

				if( addr ){
					ms_message("Match: name=%s, addr=%s", linphone_friend_get_name(lf), addr);
					gtk_list_store_insert_with_values(list, &iter, -1,
													  0, addr,
													  1, COMPLETION_LDAP, -1);
					ms_free(addr);
				}
			}
		}
		friends = friends->next;
	}
	gtk_entry_completion_complete(gtk_entry_get_completion(uribar));
}


void test_btn_clicked_cb(GtkWidget *button)
{
	ms_message("test_button_clicked_cb");
	LinphoneCore* core = linphone_gtk_get_core();
	GtkWidget *uri_bar=linphone_gtk_get_widget(linphone_gtk_get_main_window(),"uribar");
	const gchar* pred = gtk_entry_buffer_get_text(gtk_entry_get_buffer((GtkEntry*)uri_bar));

	linphone_core_ldap_launch_search(core, pred, test_cb, (void*)0x12345678);
}

void linphone_gtk_internet_kind_changed(GtkWidget *combo){
	int netkind_id=gtk_combo_box_get_active(GTK_COMBO_BOX(combo));
	LinphoneCore *lc=linphone_gtk_get_core();
	if (netkind_id==NetworkKindAdsl){
		linphone_core_set_upload_bandwidth(lc,256);
		linphone_core_set_download_bandwidth(lc,512);
	}else if (netkind_id==NetworkKindOpticalFiber){
		linphone_core_set_upload_bandwidth(lc,512);
		linphone_core_set_download_bandwidth(lc,512);
	}
}
