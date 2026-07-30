// Native tray application built with YAD dialogs (no browser/server).
package main

import (
	"encoding/json"
	"fmt"
	"github.com/codepiper/vpnctl/internal/profile"
	"github.com/codepiper/vpnctl/internal/store"
	"github.com/codepiper/vpnctl/internal/strongswan"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type state struct {
	Name      string
	Connected bool
}

func main() {
	a := os.Args[1:]
	if len(a) > 0 {
		switch a[0] {
		case "--window":
			_ = exec.Command(os.Args[0], "--tray").Start()
			window()
			return
		case "--tray":
			tray()
			return
		case "--connect":
			connect()
			return
		case "--disconnect":
			disconnect()
			return
		}
	}
	tray()
}
func yad(a ...string) (string, error) {
	o, e := exec.Command("yad", a...).Output()
	return strings.TrimSpace(string(o)), e
}
func alert(k, s string) { _, _ = yad("--"+k, "--title=PiperSec", "--text="+s, "--button=Fechar:0") }
func stateFile() string { d, _ := os.UserConfigDir(); return filepath.Join(d, "vpnctl", "tray.json") }
func load() state {
	b, e := os.ReadFile(stateFile())
	if e != nil {
		return state{}
	}
	var s state
	_ = json.Unmarshal(b, &s)
	return s
}
func save(s state) { b, _ := json.Marshal(s); _ = os.WriteFile(stateFile(), b, 0600) }
func tray() {
	_ = os.MkdirAll(filepath.Dir(stateFile()), 0700)
	lock, err := os.OpenFile(stateFile()+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
	s := load()
	tip := "PiperSec — Desconectada"
	icon := "network-vpn"
	if s.Connected {
		tip = "PiperSec — Conectada: " + s.Name
		icon = "network-transmit-receive"
	}
	c := exec.Command("yad", "--notification", "--image="+icon, "--text="+tip, "--command=vpnctl-gui --window", "--menu=Abrir PiperSec!vpnctl-gui --window|Conectar!vpnctl-gui --connect|Desconectar!vpnctl-gui --disconnect||Sair!kill $PPID", "--no-middle", "--listen")
	in, e := c.StdinPipe()
	if e != nil || c.Start() != nil {
		return
	}
	last := s
	for range time.Tick(3 * time.Second) {
		n := load()
		if n != last {
			t := "PiperSec — Desconectada"
			i := "network-vpn"
			if n.Connected {
				t = "PiperSec — Conectada: " + n.Name
				i = "network-transmit-receive"
			}
			_, _ = fmt.Fprintf(in, "tooltip:%s\nicon:%s\n", t, i)
			last = n
		}
	}
}
func all() (*store.Store, []profile.Profile, error) {
	s, e := store.Default()
	if e != nil {
		return nil, nil, e
	}
	p, e := s.List()
	return s, p, e
}
func choose(title string) (*store.Store, profile.Profile, bool) {
	s, ps, e := all()
	if e != nil {
		alert("error", e.Error())
		return nil, profile.Profile{}, false
	}
	if len(ps) == 0 {
		alert("info", "Nenhum perfil salvo. Abra PiperSec e escolha Novo perfil.")
		return s, profile.Profile{}, false
	}
	a := []string{"--list", "--title=" + title, "--text=Escolha um perfil", "--column=Perfil", "--column=Gateway", "--print-column=1"}
	for _, p := range ps {
		a = append(a, p.Name, p.RemoteAddress)
	}
	n, e := yad(a...)
	if e != nil || n == "" {
		return s, profile.Profile{}, false
	}
	p, e := s.Get(n)
	return s, p, e == nil
}
func window() {
	x, e := yad("--list", "--title=PiperSec", "--text=VPN IPsec", "--column=Ação", "Novo perfil", "Conectar", "Desconectar", "Sair")
	if e != nil {
		return
	}
	switch x {
	case "Novo perfil":
		create()
	case "Conectar":
		connect()
	case "Desconectar":
		disconnect()
	}
}
func create() {
	n, e := yad("--entry", "--title=PiperSec", "--text=Nome do perfil")
	if e != nil || n == "" {
		return
	}
	p := profile.Defaults(n)
	p.RemoteAddress, e = yad("--entry", "--title=PiperSec", "--text=Gateway VPN")
	if e != nil {
		return
	}
	p.XAuthUsername, e = yad("--entry", "--title=PiperSec", "--text=Usuário XAuth")
	if e != nil {
		return
	}
	p.PSKIdentity, e = yad("--entry", "--title=PiperSec", "--text=Identidade PSK (normalmente o gateway)")
	if e != nil {
		return
	}
	p.XAuthPassword, e = yad("--entry", "--hide-text", "--title=PiperSec", "--text=Senha XAuth")
	if e != nil {
		return
	}
	p.PSK, e = yad("--entry", "--hide-text", "--title=PiperSec", "--text=Chave PSK")
	if e != nil {
		return
	}
	s, e := store.Default()
	if e == nil {
		e = s.Put(p)
	}
	if e != nil {
		alert("error", e.Error())
	} else {
		alert("info", "Perfil salvo com configuração recomendada IKEv1/XAuth.")
	}
}
func connect() {
	_, p, ok := choose("Conectar")
	if !ok {
		return
	}
	e := strongswan.EnsureGraphicalPrerequisites()
	if e == nil {
		e = strongswan.NewGraphical().Connect(p)
	}
	if e != nil {
		alert("error", e.Error())
		return
	}
	save(state{Name: p.Name, Connected: true})
	alert("info", "VPN conectada: "+p.Name)
}
func disconnect() {
	_, p, ok := choose("Desconectar")
	if !ok {
		return
	}
	e := strongswan.EnsureGraphicalPrerequisites()
	if e == nil {
		e = strongswan.NewGraphical().Disconnect(p)
	}
	if e != nil {
		alert("error", e.Error())
		return
	}
	save(state{})
	alert("info", "VPN desconectada: "+p.Name)
}
