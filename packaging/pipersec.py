#!/usr/bin/env python3
import gi, json, subprocess, threading, time
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import Gtk, AyatanaAppIndicator3, Gdk, Gio, GLib

DEFAULTS = {"version":1,"aggressive":True,"virtual_ip":"0.0.0.0","pull":True,"ike_proposal":"aes256-sha256-ecp384","esp_proposal":"aes256-sha256-ecp384","reauth_time":"43200s","dpd_delay":"30s","dpd_timeout":"150s","remote_ts":"0.0.0.0/0","life_time":"43200s","rekey_time":"38880s"}

POLL_MS = 2000

def run(args, data=None):
    p=subprocess.run(["/usr/bin/vpnctl"]+args,input=data,text=True,capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or "Operação não concluída")
    return p.stdout

def profiles():
    return json.loads(run(["gui-list"]))

def query_sas(name):
    return json.loads(run(["gui-sas", name]))

def human_rate(bytes_per_sec):
    if bytes_per_sec >= 1024*1024:
        return "%.1f MB/s" % (bytes_per_sec/(1024*1024))
    if bytes_per_sec >= 1024:
        return "%.1f KB/s" % (bytes_per_sec/1024)
    return "%d B/s" % bytes_per_sec

class PiperSec(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="br.com.codepiper.PiperSec")
        self._prevs = {}
        self._rates = {}
        self._connected_names = set()
        self._profiles = {}

    def do_activate(self):
        self.win=Gtk.ApplicationWindow(application=self)
        self.win.set_title("PiperSec — Conexão VPN via IpSec")
        self.win.set_default_size(820,560)
        self.ind=AyatanaAppIndicator3.Indicator.new("pipersec","br.com.codepiper.PiperSec",AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        menu=Gtk.Menu()
        self.menu_status=Gtk.MenuItem(label="● VPN desconectada")
        self.menu_status.set_sensitive(False)
        menu.append(self.menu_status)
        menu.append(Gtk.SeparatorMenuItem())
        item=Gtk.MenuItem(label="Abrir PiperSec")
        item.connect("activate",lambda *_:self.show())
        menu.append(item)
        item=Gtk.MenuItem(label="Sair")
        item.connect("activate",lambda *_:self.quit_app())
        menu.append(item)
        menu.show_all()
        self.ind.set_menu(menu)

        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=10,margin=16)
        self.win.add(box)
        title=Gtk.Label()
        title.set_markup("<span size='x-large' weight='bold'>PiperSec</span>\nConexão VPN via IpSec, simples e segura")
        title.set_xalign(0)
        box.pack_start(title,False,False,0)

        self.status_label=Gtk.Label(xalign=0)
        self.status_label.set_markup("<span foreground='#777'><b>● Consultando estado…</b></span>")
        box.pack_start(self.status_label,False,False,0)

        self.rate_label=Gtk.Label(xalign=0)
        self.rate_label.set_markup("<span foreground='#555'>Sem tráfego de rede até agora.</span>")
        box.pack_start(self.rate_label,False,False,0)

        self.store=Gtk.ListStore(str,str,str,str,str)
        self.tree=Gtk.TreeView(model=self.store)
        for n,i in [("Perfil",0),("Gateway",1),("Usuário",2),("Estado",3),("Rede",4)]:
            col=Gtk.TreeViewColumn(n,Gtk.CellRendererText(),text=i)
            col.set_expand(i in (0,1))
            self.tree.append_column(col)
        self.state_col=self.tree.get_column(3)
        self.state_renderer=self.state_col.get_cells()[0]
        self.state_col.set_cell_data_func(self.state_renderer,self.render_state_color)
        self.profile_renderer=self.tree.get_column(0).get_cells()[0]
        self.tree.get_column(0).set_cell_data_func(self.profile_renderer,self.render_profile_color)
        self.tree.get_selection().set_mode(Gtk.SelectionMode.SINGLE)
        self.tree.get_selection().connect("changed",self.on_selection_changed)
        self.tree.connect("row-activated",lambda *_:(self.toggle_selected(),None)[1])
        self.tree.connect("button-press-event",self.on_tree_button)
        box.pack_start(self.tree,True,True,0)

        bar=Gtk.Box(spacing=8)
        box.pack_start(bar,False,False,0)
        self.action_buttons=[]
        self.toggle_btn=Gtk.Button(label="Conectar")
        self.toggle_btn.connect("clicked",lambda _:self.toggle_selected())
        bar.pack_start(self.toggle_btn,False,False,0)
        self.action_buttons.append(self.toggle_btn)
        for label,fn in [("Novo perfil",self.edit),("Editar perfil",self.edit_selected),("Atualizar",self.refresh),("Logs",self.show_logs)]:
            b=Gtk.Button(label=label)
            b.connect("clicked",lambda _,f=fn:f())
            bar.pack_start(b,False,False,0)
            self.action_buttons.append(b)

        self.ctx_menu=Gtk.Menu()
        for label,fn in [("Conectar",self.connect),("Desconectar",self.disconnect),("Editar perfil",self.edit_selected)]:
            item=Gtk.MenuItem(label=label)
            item.connect("activate",lambda _,f=fn:f())
            self.ctx_menu.append(item)
        self.ctx_menu.show_all()

        self.win.connect("delete-event",lambda *_:(self.win.hide(),True)[1])
        self.create_logs_window()
        self.refresh()
        GLib.timeout_add(POLL_MS, self.poll_status)
        self.win.show_all()

    def create_logs_window(self):
        self.logs_window=Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        self.logs_window.set_title("PiperSec — Logs do strongSwan")
        self.logs_window.set_default_size(820,520)
        self.logs_window.set_resizable(True)
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=6,margin=10)
        self.logs_window.add(box)
        toolbar=Gtk.Box(spacing=6)
        box.pack_start(toolbar,False,False,0)
        self.logs_refresh_btn=Gtk.Button(label="Atualizar")
        self.logs_refresh_btn.connect("clicked",lambda _:self.refresh_logs())
        toolbar.pack_start(self.logs_refresh_btn,False,False,0)
        self.logs_clear_btn=Gtk.Button(label="Limpar")
        self.logs_clear_btn.connect("clicked",lambda _:self.clear_logs())
        toolbar.pack_start(self.logs_clear_btn,False,False,0)
        self.logs_auto_scroll=Gtk.CheckButton(label="Rolagem automática")
        self.logs_auto_scroll.set_active(True)
        toolbar.pack_start(self.logs_auto_scroll,False,False,0)
        toolbar.pack_end(Gtk.Label(label="Últimas 200 linhas do serviço strongSwan"),True,True,0)
        self.logs_view=Gtk.TextView()
        self.logs_view.set_editable(False)
        self.logs_view.set_monospace(True)
        self.logs_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.logs_buffer=self.logs_view.get_buffer()
        sw=Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC,Gtk.PolicyType.AUTOMATIC)
        sw.add(self.logs_view)
        box.pack_start(sw,True,True,0)
        self.logs_window.connect("delete-event",lambda *_:(self.logs_window.hide(),True)[1])
        self.logs_window.show_all()

    def set_overall_status(self, connected, detail=""):
        if connected:
            text="Conectada: "+detail
            color="#35a854"
            icon="network-transmit-receive"
            menu="● Conectada: "+detail
        else:
            text="Desconectada"
            color="#d9534f"
            icon="network-vpn"
            menu="● VPN desconectada"
        self.ind.set_icon_full(icon,"PiperSec — "+text)
        self.menu_status.set_label(menu)
        self.status_label.set_markup("<span foreground='%s'><b>● %s</b></span>" % (color,text))

    def update_rates(self, name, sas, now):
        total_in=sum(c["bytes_in"] for c in sas["children"])
        total_out=sum(c["bytes_out"] for c in sas["children"])
        prev=self._prevs.get(name)
        self._prevs[name]=(total_in,total_out,now)
        if not prev:
            return
        dt=max(now-prev[2],0.001)
        ri=max(total_in-prev[0],0)/dt
        ro=max(total_out-prev[1],0)/dt
        self._rates[name]=(ri,ro)

    def poll_status(self):
        def worker():
            results={}
            try:
                names=[p["name"] for p in profiles()]
            except Exception:
                names=[]
            for name in names:
                try:
                    results[name]=query_sas(name)
                except Exception:
                    results[name]=None
            GLib.idle_add(self.apply_status,results)
        threading.Thread(target=worker,daemon=True).start()
        return True

    def apply_status(self, results):
        now=time.monotonic()
        connected_names=[]
        for name,sas in results.items():
            if sas and sas.get("connected"):
                connected_names.append(name)
                self.update_rates(name,sas,now)
        self._connected_names=set(connected_names)

        if connected_names:
            detail=", ".join(connected_names)
            self.set_overall_status(True,detail)
        else:
            self.set_overall_status(False)

        total_ri,total_ro=0,0
        for name in connected_names:
            ri,ro=self._rates.get(name,(0,0))
            total_ri+=ri
            total_ro+=ro
        if total_ri or total_ro:
            self.rate_label.set_markup("<span foreground='#1769e0'><b>↓ Recebendo %s   ↑ Enviando %s</b></span>" % (human_rate(total_ri),human_rate(total_ro)))
        elif connected_names:
            self.rate_label.set_markup("<span foreground='#555'>Conectado, aguardando tráfego…</span>")
        else:
            self.rate_label.set_markup("<span foreground='#555'>Sem tráfego de rede até agora.</span>")

        self.render_rows()
        return False

    def render_rows(self):
        self.store.clear()
        for p in self._profiles.values():
            name=p["name"]
            conn=name in self._connected_names
            state="● Conectado" if conn else "—"
            ri,ro=self._rates.get(name,(0,0))
            net="↓%s  ↑%s" % (human_rate(ri),human_rate(ro)) if conn else ""
            self.store.append([name,p["remote_address"],p["xauth_username"],state,net])
        self.update_toggle_label()

    def render_state_color(self, col, renderer, model, it, data=None):
        connected=self.store.get_value(it,3).startswith("●")
        renderer.set_property("foreground","#35a854" if connected else "#999999")

    def render_profile_color(self, col, renderer, model, it, data=None):
        connected=self.store.get_value(it,3).startswith("●")
        renderer.set_property("foreground","#000000" if connected else "#000000")
        renderer.set_property("weight",700 if connected else 400)

    def on_selection_changed(self, selection):
        self.update_toggle_label()

    def update_toggle_label(self):
        name=self.selected_name()
        if not name:
            self.toggle_btn.set_label("Conectar")
            self.toggle_btn.set_sensitive(False)
            return
        self.toggle_btn.set_sensitive(True)
        self.toggle_btn.set_label("Desconectar" if name in self._connected_names else "Conectar")

    def selected_name(self):
        m,it=self.tree.get_selection().get_selected()
        return m[it][0] if it else None

    def toggle_selected(self):
        name=self.selected_name()
        if not name:
            self.error("Selecione um perfil.")
            return
        if name in self._connected_names:
            self.start_vpn_action("gui-disconnect",name)
        else:
            self.start_vpn_action("gui-connect",name)

    def on_tree_button(self, tree, event):
        if event.button==3:
            path=tree.get_path_at_pos(int(event.x),int(event.y))
            if path:
                tree.get_selection().select_path(path[0])
                self.ctx_menu.popup(None,None,None,None,event.button,event.time)
            return True
        return False

    def notify(self, title, body):
        note=Gio.Notification.new(title)
        note.set_body(body)
        self.send_notification("vpn-status",note)

    def set_busy(self, busy, message=""):
        for button in self.action_buttons:
            button.set_sensitive(not busy)
        if busy:
            self.status_label.set_markup("<span foreground='#d88a00'><b>● %s</b></span>" % message)

    def finish_vpn_action(self, command, profile, error):
        self.set_busy(False)
        if error:
            self.error(error)
            return False
        if command == "gui-connect":
            self.notify("VPN conectada","PiperSec conectou o perfil "+profile)
        else:
            self.notify("VPN desconectada","PiperSec desconectou o perfil "+profile)
        self.update_toggle_label()
        GLib.idle_add(self.poll_status)
        return False

    def quit_app(self):
        if hasattr(self,"logs_window"):
            self.logs_window.destroy()
        self.quit()

    def show(self):
        if not hasattr(self,"win"):
            self.activate()
        self.win.show_all()
        self.win.present()

    def refresh(self):
        try:
            self._profiles={p["name"]:p for p in profiles()}
            self.render_rows()
        except Exception as e:
            self.error(str(e))

    def selected(self):
        name=self.selected_name()
        if not name:
            self.error("Selecione um perfil.")
            return None
        return name

    def edit_selected(self):
        n=self.selected()
        if n:
            self.edit(self._profiles[n])

    def edit(self, existing=None):
        p=dict(DEFAULTS)
        p.update(existing or {})
        title="Editar perfil" if existing else "Novo perfil"
        d=Gtk.Dialog(title=title,transient_for=self.win,flags=0)
        d.set_default_size(620,560)
        d.add_buttons("Cancelar",Gtk.ResponseType.CANCEL,"Salvar perfil",Gtk.ResponseType.OK)
        notebook=Gtk.Notebook()
        notebook.set_border_width(18)
        d.get_content_area().add(notebook)
        basic=Gtk.Grid(column_spacing=14,row_spacing=10)
        setup=Gtk.Grid(column_spacing=14,row_spacing=10)
        advanced=Gtk.Grid(column_spacing=14,row_spacing=10)
        notebook.append_page(basic,Gtk.Label(label="Essencial"))
        notebook.append_page(setup,Gtk.Label(label="Conexão"))
        notebook.append_page(advanced,Gtk.Label(label="Avançado"))
        fields={}
        def text(grid,row,label,key,tip,secret=False,readonly=False):
            l=Gtk.Label(label=label,xalign=0)
            l.set_tooltip_text(tip)
            grid.attach(l,0,row,1,1)
            e=Gtk.Entry()
            e.set_text(str(p.get(key,"")))
            e.set_visibility(not secret)
            e.set_tooltip_text(tip)
            e.set_sensitive(not readonly)
            grid.attach(e,1,row,1,1)
            fields[key]=e
        text(basic,0,"Nome do perfil","name","Um nome curto para identificar a VPN.",False,existing is not None)
        text(basic,1,"Gateway VPN","remote_address","IP ou endereço DNS fornecido pela empresa.")
        text(basic,2,"Usuário XAuth","xauth_username","Usuário de autenticação da VPN.")
        text(basic,3,"Senha XAuth","xauth_password","Deixe vazio ao editar para manter a senha atual.",True)
        text(basic,4,"Identidade PSK","psk_identity","Normalmente o IP ou DNS do gateway.")
        text(basic,5,"Chave PSK","psk","Chave pré-compartilhada. Deixe vazio ao editar para manter.",True)
        version=Gtk.ComboBoxText()
        version.append("1","IKEv1 — XAuth / PSK")
        version.append("2","IKEv2 — moderno")
        version.set_active_id(str(p["version"]))
        version.set_tooltip_text("Escolha IKEv1 para configurações como a Unimed.")
        setup.attach(Gtk.Label(label="Versão IKE",xalign=0),0,0,1,1)
        setup.attach(version,1,0,1,1)
        aggressive=Gtk.CheckButton(label="Modo agressivo (somente IKEv1)")
        aggressive.set_active(p["aggressive"])
        aggressive.set_tooltip_text("Ative apenas se a configuração do administrador indicar aggressive=yes.")
        setup.attach(aggressive,1,1,1,1)
        pull=Gtk.CheckButton(label="Solicitar configurações ao servidor")
        pull.set_active(p["pull"])
        pull.set_tooltip_text("Equivale a pull=yes.")
        setup.attach(pull,1,2,1,1)
        text(setup,3,"IP virtual solicitado","virtual_ip","Use 0.0.0.0 para receber IP virtual do servidor.")
        text(setup,4,"Rede remota","remote_ts","0.0.0.0/0 envia todo o tráfego pelo túnel.")
        def combo(row,label,key,tip):
            c=Gtk.ComboBoxText()
            opts=["aes256-sha256-ecp384","aes256-sha256-modp2048","aes256-sha256-modp3072","aes128-sha256-modp2048"]
            [c.append_text(x) for x in opts]
            c.set_active(opts.index(p[key]) if p[key] in opts else 0)
            c.set_tooltip_text(tip)
            advanced.attach(Gtk.Label(label=label,xalign=0),0,row,1,1)
            advanced.attach(c,1,row,1,1)
            fields[key]=c
        combo(0,"Proposta IKE","ike_proposal","Algoritmos da negociação IKE. Use o valor recebido do administrador.")
        combo(1,"Proposta ESP","esp_proposal","Algoritmos do túnel IPsec (ESP).")
        text(advanced,2,"Reautenticação","reauth_time","Ex.: 43200s = 12 horas.")
        text(advanced,3,"DPD intervalo","dpd_delay","Frequência de verificação do gateway.")
        text(advanced,4,"DPD timeout","dpd_timeout","Tempo até considerar o gateway inativo.")
        text(advanced,5,"Vida do túnel","life_time","Tempo máximo do Child SA.")
        text(advanced,6,"Rekey","rekey_time","Quando renovar as chaves do túnel.")
        d.show_all()
        if d.run()==Gtk.ResponseType.OK:
            q=dict(p)
            for key,w in fields.items():
                q[key]=w.get_active_text() if isinstance(w,Gtk.ComboBoxText) else w.get_text().strip()
            q["version"]=int(version.get_active_id())
            q["aggressive"]=aggressive.get_active()
            q["pull"]=pull.get_active()
            try:
                run(["gui-save"],json.dumps(q))
                self.refresh()
            except Exception as e:
                self.error(str(e))
        d.destroy()

    def connect(self):
        n=self.selected()
        if n:
            self.start_vpn_action("gui-connect",n)

    def disconnect(self):
        n=self.selected()
        if n:
            self.start_vpn_action("gui-disconnect",n)

    def error(self,t):
        self.message(Gtk.MessageType.ERROR,t)

    def info(self,t):
        self.message(Gtk.MessageType.INFO,t)

    def message(self,k,t):
        d=Gtk.MessageDialog(transient_for=self.win,flags=0,message_type=k,buttons=Gtk.ButtonsType.OK,text=t)
        d.run()
        d.destroy()

    def show_logs(self):
        if hasattr(self,"logs_window"):
            self.logs_window.show_all()
            self.logs_window.present()
            self.refresh_logs()

    def refresh_logs(self):
        self.logs_refresh_btn.set_sensitive(False)
        def worker():
            try:
                out=run(["gui-logs"])
            except Exception as e:
                out="Erro ao obter logs: "+str(e)
            GLib.idle_add(self.logs_ready,out)
        threading.Thread(target=worker,daemon=True).start()

    def logs_ready(self, out):
        self.logs_refresh_btn.set_sensitive(True)
        self.logs_buffer.set_text("")
        end=self.logs_buffer.get_end_iter()
        self.logs_buffer.insert(end,out)
        if self.logs_auto_scroll.get_active():
            mark=self.logs_buffer.create_mark(None,end,False)
            self.logs_view.scroll_to_mark(mark,0.0,False,0.0,0.0)

    def clear_logs(self):
        self.logs_buffer.set_text("")

app=PiperSec()
app.run(None)