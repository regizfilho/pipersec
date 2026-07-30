//go:build web

// Optional browser interface retained for development only.
package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/codepiper/vpnctl/internal/profile"
	"github.com/codepiper/vpnctl/internal/store"
	"github.com/codepiper/vpnctl/internal/strongswan"
)

type ui struct{ store *store.Store }
type view struct {
	Profiles               []profile.Profile
	P                      profile.Profile
	Edit                   bool
	Message, Error, Status string
}

//go:embed ux.html
var ux string

var layout = template.Must(template.New("ui").Funcs(template.FuncMap{"dict": dict}).Parse(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VPN IPsec</title><style>body{margin:0;background:#f4f7fb;color:#172033;font:16px system-ui}main{max-width:1050px;margin:28px auto;padding:0 18px}.card{background:white;border-radius:14px;padding:22px;margin:16px 0;box-shadow:0 3px 16px #18243b12}h1{margin:0}p{color:#56657d}.actions{display:flex;flex-wrap:wrap;gap:8px}.button,button{border:0;border-radius:8px;padding:9px 13px;background:#1769e0;color:white;text-decoration:none;font:inherit;cursor:pointer}.secondary{background:#e6edf8;color:#153561}.danger{background:#bd3232}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #e4eaf4;padding:10px 6px}label{display:block;font-weight:600;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:9px;border:1px solid #bbc8da;border-radius:7px;font:inherit}.check{font-weight:400}.check input{width:auto}.notice{padding:11px;background:#e9f2ff;border-radius:7px}.error{padding:11px;background:#ffeaea;color:#9b1f1f;border-radius:7px}pre{white-space:pre-wrap;background:#121b2a;color:#eef5ff;padding:14px;border-radius:8px}@media(max-width:650px){table,tbody,tr,td{display:block}thead{display:none}td{border:0}}</style><main><h1>VPN IPsec</h1><p>Perfis strongSwan salvos de forma cifrada neste computador.</p>{{if .Error}}<div class="error">{{.Error}}</div>{{end}}{{if .Message}}<div class="notice">{{.Message}}</div>{{end}}{{if .Status}}<div class="card"><h2>Estado: {{.P.Name}}</h2><pre>{{.Status}}</pre><a class="button secondary" href="/">Voltar</a></div>{{else if .Edit}}{{template "form" .}}{{else}}{{template "list" .}}{{end}}</main></html>{{define "list"}}<div class="card"><div class="actions"><a class="button" href="/profile">Novo perfil</a><a class="button secondary" href="/">Atualizar</a></div></div><div class="card"><h2>Perfis salvos</h2>{{if .Profiles}}<table><thead><tr><th>Nome</th><th>Gateway</th><th>Usuário</th><th>Ações</th></tr></thead><tbody>{{range .Profiles}}<tr><td><b>{{.Name}}</b></td><td>{{.RemoteAddress}}</td><td>{{.XAuthUsername}}</td><td><div class="actions"><a class="button secondary" href="/profile?name={{.Name}}">Editar</a><form method="post" action="/connect"><input type="hidden" name="name" value="{{.Name}}"><button>Conectar</button></form><form method="post" action="/disconnect"><input type="hidden" name="name" value="{{.Name}}"><button class="secondary">Desconectar</button></form><a class="button secondary" href="/status?name={{.Name}}">Estado</a><form method="post" action="/delete"><input type="hidden" name="name" value="{{.Name}}"><button class="danger">Excluir</button></form></div></td></tr>{{end}}</tbody></table>{{else}}<p>Nenhum perfil criado.</p>{{end}}</div><div class="card"><b>Conectar não abre terminal.</b><p>O Linux exibirá a janela gráfica de autorização administrativa.</p></div>{{end}}{{define "form"}}<div class="card"><h2>{{if .P.Name}}Editar {{.P.Name}}{{else}}Novo perfil{{end}}</h2><p>Deixe as senhas vazias para mantê-las. Elas nunca são exibidas após salvar.</p><form method="post" action="/save">{{template "input" dict "Nome" "name" .P.Name "ex.: matriz" "text"}}{{template "input" dict "Gateway VPN" "remote" .P.RemoteAddress "vpn.empresa.com" "text"}}{{template "input" dict "Versão IKE" "version" .P.Version "1 ou 2" "number"}}{{template "input" dict "Usuário XAuth" "user" .P.XAuthUsername "usuário" "text"}}{{template "input" dict "Senha XAuth" "password" "" "vazio mantém" "password"}}{{template "input" dict "Identidade PSK" "psk_id" .P.PSKIdentity "gateway ou ID informado" "text"}}{{template "input" dict "Chave PSK" "psk" "" "vazio mantém" "password"}}<h2>Avançado</h2>{{template "input" dict "VIP" "vip" .P.VirtualIP "0.0.0.0" "text"}}{{template "input" dict "Rede remota" "remote_ts" .P.RemoteTS "0.0.0.0/0" "text"}}{{template "input" dict "Proposta IKE" "ike" .P.IKEProposal "" "text"}}{{template "input" dict "Proposta ESP" "esp" .P.ESPProposal "" "text"}}{{template "input" dict "Reautenticação" "reauth" .P.ReauthTime "43200s" "text"}}{{template "input" dict "DPD intervalo" "dpd_delay" .P.DPDDelay "30s" "text"}}{{template "input" dict "DPD timeout" "dpd_timeout" .P.DPDTimeout "150s" "text"}}{{template "input" dict "Vida do túnel" "life" .P.LifeTime "43200s" "text"}}{{template "input" dict "Rekey" "rekey" .P.RekeyTime "38880s" "text"}}<label class="check"><input type="checkbox" name="aggressive" {{if .P.Aggressive}}checked{{end}}> Modo agressivo (IKEv1)</label><label class="check"><input type="checkbox" name="pull" {{if .P.Pull}}checked{{end}}> Solicitar configuração ao servidor</label><p class="actions"><button>Salvar</button><a class="button secondary" href="/">Cancelar</a></p></form></div>{{end}}{{define "input"}}<label>{{index . 0}}</label><input name="{{index . 1}}" value="{{index . 2}}" placeholder="{{index . 3}}" type="{{index . 4}}">{{end}}`))

func dict(values ...any) []any { return values }
func main() {
	s, e := store.Default()
	if e != nil {
		panic(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:8179")
	if e != nil {
		_ = exec.Command("gio", "open", "http://127.0.0.1:8179").Start()
		return
	}
	u := &ui{store: s}
	m := http.NewServeMux()
	m.HandleFunc("/", u.home)
	m.HandleFunc("/profile", u.form)
	m.HandleFunc("/save", u.save)
	m.HandleFunc("/connect", u.connect)
	m.HandleFunc("/disconnect", u.disconnect)
	m.HandleFunc("/delete", u.delete)
	m.HandleFunc("/status", u.status)
	go func() {
		_ = exec.Command("gio", "open", "http://127.0.0.1:8179").Start()
	}()
	panic(http.Serve(l, m))
}
func render(w http.ResponseWriter, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var out bytes.Buffer
	_ = layout.Execute(&out, v)
	html := strings.ReplaceAll(out.String(), "VPN IPsec", "PiperSec - Conexão VPN via IpSec")
	_, _ = w.Write([]byte(strings.Replace(html, "</main></html>", ux+"</main></html>", 1)))
}
func (u *ui) home(w http.ResponseWriter, r *http.Request) {
	p, e := u.store.List()
	render(w, view{Profiles: p, Message: r.URL.Query().Get("message"), Error: errorText(e)})
}
func (u *ui) form(w http.ResponseWriter, r *http.Request) {
	n := r.URL.Query().Get("name")
	p := profile.Defaults("")
	var e error
	if n != "" {
		p, e = u.store.Get(n)
	}
	render(w, view{P: p, Edit: true, Error: errorText(e)})
}
func v(r *http.Request, k string) string { return strings.TrimSpace(r.FormValue(k)) }
func errorText(e error) string {
	if e != nil {
		return e.Error()
	}
	return ""
}
func goHome(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?message="+url.QueryEscape(msg), 303)
}
func (u *ui) save(w http.ResponseWriter, r *http.Request) {
	n := v(r, "name")
	p := profile.Defaults(n)
	if old, e := u.store.Get(n); e == nil {
		p = old
	}
	version, e := strconv.Atoi(v(r, "version"))
	if e != nil {
		render(w, view{P: p, Edit: true, Error: "Versão IKE inválida."})
		return
	}
	p.Name, p.RemoteAddress, p.Version = n, v(r, "remote"), version
	p.XAuthUsername, p.PSKIdentity = v(r, "user"), v(r, "psk_id")
	p.VirtualIP, p.RemoteTS = v(r, "vip"), v(r, "remote_ts")
	p.IKEProposal, p.ESPProposal = v(r, "ike"), v(r, "esp")
	p.ReauthTime, p.DPDDelay, p.DPDTimeout = v(r, "reauth"), v(r, "dpd_delay"), v(r, "dpd_timeout")
	p.LifeTime, p.RekeyTime = v(r, "life"), v(r, "rekey")
	p.Aggressive, p.Pull = r.FormValue("aggressive") != "", r.FormValue("pull") != ""
	if r.FormValue("password") != "" {
		p.XAuthPassword = r.FormValue("password")
	}
	if r.FormValue("psk") != "" {
		p.PSK = r.FormValue("psk")
	}
	if e = u.store.Put(p); e != nil {
		render(w, view{P: p, Edit: true, Error: e.Error()})
		return
	}
	goHome(w, r, "Perfil salvo.")
}
func (u *ui) profile(r *http.Request) (profile.Profile, error) { return u.store.Get(v(r, "name")) }
func (u *ui) delete(w http.ResponseWriter, r *http.Request) {
	p, e := u.profile(r)
	if e == nil {
		e = u.store.Delete(p.Name)
	}
	if e != nil {
		render(w, view{Error: e.Error()})
		return
	}
	goHome(w, r, "Perfil removido.")
}
func (u *ui) action(w http.ResponseWriter, r *http.Request, fn func(*strongswan.Client, profile.Profile) error, ok string) {
	p, e := u.profile(r)
	if e == nil {
		e = strongswan.EnsureGraphicalPrerequisites()
	}
	if e == nil {
		e = fn(strongswan.NewGraphical(), p)
	}
	if e != nil {
		render(w, view{Error: e.Error()})
		return
	}
	goHome(w, r, ok+p.Name)
}
func (u *ui) connect(w http.ResponseWriter, r *http.Request) {
	u.action(w, r, func(c *strongswan.Client, p profile.Profile) error { return c.Connect(p) }, "Conectado: ")
}
func (u *ui) disconnect(w http.ResponseWriter, r *http.Request) {
	u.action(w, r, func(c *strongswan.Client, p profile.Profile) error { return c.Disconnect(p) }, "Desconectado: ")
}
func (u *ui) status(w http.ResponseWriter, r *http.Request) {
	p, e := u.profile(r)
	if e == nil {
		e = strongswan.EnsureGraphicalPrerequisites()
	}
	if e != nil {
		render(w, view{Error: e.Error()})
		return
	}
	out, e := strongswan.NewGraphical().Status(p.Name)
	render(w, view{P: p, Status: out, Error: errorText(e)})
}
