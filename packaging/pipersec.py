#!/usr/bin/python3
import gi, json, subprocess, threading
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import Gtk, AyatanaAppIndicator3, Gdk, Gio, GLib

DEFAULTS = {"version":1,"aggressive":True,"virtual_ip":"0.0.0.0","pull":True,"ike_proposal":"aes256-sha256-ecp384","esp_proposal":"aes256-sha256-ecp384","reauth_time":"43200s","dpd_delay":"30s","dpd_timeout":"150s","remote_ts":"0.0.0.0/0","life_time":"43200s","rekey_time":"38880s"}
def run(args, data=None):
    p=subprocess.run(["/usr/bin/vpnctl"]+args,input=data,text=True,capture_output=True)
    if p.returncode: raise RuntimeError(p.stderr.strip() or "Operação não concluída")
    return p.stdout
def profiles():
    return json.loads(run(["gui-list"]))
class PiperSec(Gtk.Application):
 def __init__(self):
  super().__init__(application_id="br.com.codepiper.PiperSec")
 def do_activate(self):
  self.win=Gtk.ApplicationWindow(application=self); self.win.set_title("PiperSec — Conexão VPN via IpSec"); self.win.set_default_size(760,500)
  self.ind=AyatanaAppIndicator3.Indicator.new("pipersec","br.com.codepiper.PiperSec",AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS)
  self.ind.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
  menu=Gtk.Menu(); self.menu_status=Gtk.MenuItem(label="● VPN desconectada"); self.menu_status.set_sensitive(False); menu.append(self.menu_status)
  menu.append(Gtk.SeparatorMenuItem()); item=Gtk.MenuItem(label="Abrir PiperSec"); item.connect("activate",lambda *_:self.show()); menu.append(item)
  item=Gtk.MenuItem(label="Sair"); item.connect("activate",lambda *_:self.quit_app()); menu.append(item); menu.show_all(); self.ind.set_menu(menu)
  box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12,margin=20); self.win.add(box)
  title=Gtk.Label(); title.set_markup("<span size='x-large' weight='bold'>PiperSec</span>\nConexão VPN via IpSec, simples e segura"); title.set_xalign(0); box.pack_start(title,False,False,0)
  self.status_label=Gtk.Label(xalign=0); box.pack_start(self.status_label,False,False,0)
  self.store=Gtk.ListStore(str,str,str); self.tree=Gtk.TreeView(model=self.store)
  for n,i in [("Perfil",0),("Gateway",1),("Usuário",2)]:
   col=Gtk.TreeViewColumn(n,Gtk.CellRendererText(),text=i);self.tree.append_column(col)
  box.pack_start(self.tree,True,True,0)
  bar=Gtk.Box(spacing=8); box.pack_start(bar,False,False,0)
  self.action_buttons=[]
  for label,fn in [("Novo perfil",self.edit),("Editar perfil",self.edit_selected),("Conectar",self.connect),("Desconectar",self.disconnect),("Atualizar",self.refresh)]:
   b=Gtk.Button(label=label); b.connect("clicked",lambda _,f=fn:f()); bar.pack_start(b,False,False,0); self.action_buttons.append(b)
  self.win.connect("delete-event",lambda *_:(self.win.hide(),True)[1]); self.create_status_window(); self.update_status(); self.refresh(); self.win.show_all()
 def create_status_window(self):
  self.status_window=Gtk.Window(type=Gtk.WindowType.TOPLEVEL); self.status_window.set_decorated(False); self.status_window.set_resizable(False); self.status_window.set_keep_above(True); self.status_window.set_skip_taskbar_hint(True); self.status_window.set_type_hint(Gdk.WindowTypeHint.UTILITY)
  frame=Gtk.Frame(shadow_type=Gtk.ShadowType.OUT); self.status_window.add(frame); body=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=10,margin=10); frame.add(body)
  self.status_dot=Gtk.Label(); self.status_dot.set_markup("<span foreground='#d9534f' size='x-large'>●</span>"); body.pack_start(self.status_dot,False,False,0)
  self.status_window_label=Gtk.Label(xalign=0); body.pack_start(self.status_window_label,True,True,0)
  open_button=Gtk.Button(label="Abrir"); open_button.connect("clicked",lambda *_:self.show()); body.pack_start(open_button,False,False,0)
  self.status_window.connect("button-press-event",lambda *_:(self.show(),True)[1]); self.status_window.show_all()
  screen=self.status_window.get_screen(); self.status_window.move(max(0,screen.get_width()-310),12)
 def update_status(self, connected=False, profile=None):
  if connected:
   text="Conectada: "+profile; color="#35a854"; icon="network-transmit-receive"; menu="● Conectada: "+profile
  else:
   text="Desconectada"; color="#d9534f"; icon="network-vpn"; menu="● VPN desconectada"
  self.ind.set_icon_full(icon,"PiperSec — "+text); self.menu_status.set_label(menu)
  self.status_dot.set_markup("<span foreground='%s' size='x-large'>●</span>" % color)
  self.status_window_label.set_markup("<b>PiperSec</b>\n%s" % text)
  self.status_label.set_markup("<span foreground='%s'><b>● %s</b></span>" % (color,text))
  self.status_window.show_all()
 def notify(self, title, body):
  note=Gio.Notification.new(title); note.set_body(body); self.send_notification("vpn-status",note)
 def set_busy(self, busy, message=""):
  for button in self.action_buttons: button.set_sensitive(not busy)
  if busy: self.status_label.set_markup("<span foreground='#d88a00'><b>● %s</b></span>" % message)
 def start_vpn_action(self, command, profile):
  self.set_busy(True, "Conectando…" if command == "gui-connect" else "Desconectando…")
  def worker():
   try: result=(None,run([command,profile]))
   except Exception as error: result=(str(error),None)
   GLib.idle_add(self.finish_vpn_action,command,profile,result[0])
  threading.Thread(target=worker,daemon=True).start()
 def finish_vpn_action(self, command, profile, error):
  self.set_busy(False)
  if error: self.error(error); return False
  if command == "gui-connect":
   self.update_status(True,profile); self.notify("VPN conectada","PiperSec conectou o perfil "+profile)
  else:
   self.update_status(); self.notify("VPN desconectada","PiperSec desconectou o perfil "+profile)
  return False
 def quit_app(self):
  if hasattr(self,"status_window"): self.status_window.destroy()
  self.quit()
 def show(self):
  if not hasattr(self,"win"): self.activate()
  self.win.show_all(); self.win.present()
 def refresh(self):
  self.store.clear()
  try:
   self.profiles={p["name"]:p for p in profiles()}
   for p in self.profiles.values(): self.store.append([p["name"],p["remote_address"],p["xauth_username"]])
  except Exception as e:self.error(str(e))
 def selected(self):
  m,it=self.tree.get_selection().get_selected()
  if not it: self.error("Selecione um perfil."); return None
  return m[it][0]
 def edit_selected(self):
  n=self.selected()
  if n:self.edit(self.profiles[n])
 def edit(self, existing=None):
  p=dict(DEFAULTS);p.update(existing or {})
  title="Editar perfil" if existing else "Novo perfil"
  d=Gtk.Dialog(title=title,transient_for=self.win,flags=0);d.set_default_size(620,560);d.add_buttons("Cancelar",Gtk.ResponseType.CANCEL,"Salvar perfil",Gtk.ResponseType.OK)
  notebook=Gtk.Notebook();notebook.set_border_width(18);d.get_content_area().add(notebook);basic=Gtk.Grid(column_spacing=14,row_spacing=10);setup=Gtk.Grid(column_spacing=14,row_spacing=10);advanced=Gtk.Grid(column_spacing=14,row_spacing=10);notebook.append_page(basic,Gtk.Label(label="Essencial"));notebook.append_page(setup,Gtk.Label(label="Conexão"));notebook.append_page(advanced,Gtk.Label(label="Avançado"));fields={}
  def text(grid,row,label,key,tip,secret=False,readonly=False):
   l=Gtk.Label(label=label,xalign=0);l.set_tooltip_text(tip);grid.attach(l,0,row,1,1);e=Gtk.Entry();e.set_text(str(p.get(key,"")));e.set_visibility(not secret);e.set_tooltip_text(tip);e.set_sensitive(not readonly);grid.attach(e,1,row,1,1);fields[key]=e
  text(basic,0,"Nome do perfil","name","Um nome curto para identificar a VPN.",False,existing is not None)
  text(basic,1,"Gateway VPN","remote_address","IP ou endereço DNS fornecido pela empresa.")
  text(basic,2,"Usuário XAuth","xauth_username","Usuário de autenticação da VPN.")
  text(basic,3,"Senha XAuth","xauth_password","Deixe vazio ao editar para manter a senha atual.",True)
  text(basic,4,"Identidade PSK","psk_identity","Normalmente o IP ou DNS do gateway.")
  text(basic,5,"Chave PSK","psk","Chave pré-compartilhada. Deixe vazio ao editar para manter.",True)
  version=Gtk.ComboBoxText();version.append("1","IKEv1 — XAuth / PSK");version.append("2","IKEv2 — moderno");version.set_active_id(str(p["version"]));version.set_tooltip_text("Escolha IKEv1 para configurações como a Unimed.");setup.attach(Gtk.Label(label="Versão IKE",xalign=0),0,0,1,1);setup.attach(version,1,0,1,1)
  aggressive=Gtk.CheckButton(label="Modo agressivo (somente IKEv1)");aggressive.set_active(p["aggressive"]);aggressive.set_tooltip_text("Ative apenas se a configuração do administrador indicar aggressive=yes.");setup.attach(aggressive,1,1,1,1)
  pull=Gtk.CheckButton(label="Solicitar configurações ao servidor");pull.set_active(p["pull"]);pull.set_tooltip_text("Equivale a pull=yes.");setup.attach(pull,1,2,1,1)
  text(setup,3,"IP virtual solicitado","virtual_ip","Use 0.0.0.0 para receber IP virtual do servidor.")
  text(setup,4,"Rede remota","remote_ts","0.0.0.0/0 envia todo o tráfego pelo túnel.")
  def combo(row,label,key,tip):
   c=Gtk.ComboBoxText();opts=["aes256-sha256-ecp384","aes256-sha256-modp2048","aes256-sha256-modp3072","aes128-sha256-modp2048"];[c.append_text(x) for x in opts];c.set_active(opts.index(p[key]) if p[key] in opts else 0);c.set_tooltip_text(tip);advanced.attach(Gtk.Label(label=label,xalign=0),0,row,1,1);advanced.attach(c,1,row,1,1);fields[key]=c
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
   for key,w in fields.items():q[key]=w.get_active_text() if isinstance(w,Gtk.ComboBoxText) else w.get_text().strip()
   q["version"]=int(version.get_active_id());q["aggressive"]=aggressive.get_active();q["pull"]=pull.get_active()
   try:run(["gui-save"],json.dumps(q));self.refresh()
   except Exception as e:self.error(str(e))
  d.destroy()
 def connect(self):
  n=self.selected()
  if n:
   self.start_vpn_action("gui-connect",n)
 def disconnect(self):
  n=self.selected()
  if n:
   self.start_vpn_action("gui-disconnect",n)
 def error(self,t):self.message(Gtk.MessageType.ERROR,t)
 def info(self,t):self.message(Gtk.MessageType.INFO,t)
 def message(self,k,t):
  d=Gtk.MessageDialog(transient_for=self.win,flags=0,message_type=k,buttons=Gtk.ButtonsType.OK,text=t);d.run();d.destroy()
app=PiperSec();app.run(None)
