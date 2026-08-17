//go:build fyne

// Optional Fyne desktop implementation. The default Linux build uses the
// browser-based graphical UI in web.go to avoid native build dependencies.
package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/codepiper/vpnctl/internal/profile"
	"github.com/codepiper/vpnctl/internal/store"
	"github.com/codepiper/vpnctl/internal/strongswan"
)

type controller struct {
	window   fyne.Window
	store    *store.Store
	profiles []profile.Profile
	selected int
	list     *widget.List
	details  *widget.Label
	message  *widget.Label
	logsView *widget.Entry
}

func main() {
	a := app.NewWithID("com.codepiper.vpnctl")
	w := a.NewWindow("VPN IPsec")
	w.Resize(fyne.NewSize(960, 620))
	s, err := store.Default()
	if err != nil {
		dialog.ShowError(err, w)
		w.ShowAndRun()
		return
	}
	c := &controller{window: w, store: s, selected: -1}
	c.build()
	c.refresh()
	w.ShowAndRun()
}

func (c *controller) build() {
	c.details = widget.NewLabel("Selecione um perfil à esquerda ou crie uma nova conexão.")
	c.details.Wrapping = fyne.TextWrapWord
	c.message = widget.NewLabel("Pronto.")
	c.message.Wrapping = fyne.TextWrapWord
	c.list = widget.NewList(
		func() int { return len(c.profiles) },
		func() fyne.CanvasObject { return widget.NewLabel("perfil") },
		func(id widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(c.profiles[id].Name) },
	)
	c.list.OnSelected = func(id widget.ListItemID) { c.selected = id; c.showSelected() }

	newButton := widget.NewButton("Novo perfil", func() { c.editProfile(-1) })
	editButton := widget.NewButton("Editar", func() { c.editProfile(c.selected) })
	deleteButton := widget.NewButton("Excluir", c.deleteSelected)
	left := container.NewBorder(
		widget.NewLabel("Perfis VPN"),
		container.NewGridWithColumns(2, newButton, widget.NewButton("Atualizar", c.refresh)),
		nil, nil, c.list,
	)

	connectButton := widget.NewButton("Conectar", c.connectSelected)
	disconnectButton := widget.NewButton("Desconectar", c.disconnectSelected)
	statusButton := widget.NewButton("Ver estado", c.statusSelected)
	logsButton := widget.NewButton("Ver logs", c.showLogs)
	actions := container.NewGridWithColumns(4, connectButton, disconnectButton, statusButton, logsButton)
	c.logsView = widget.NewMultiLineEntry()
	c.logsView.SetPlaceHolder("Logs de conexão aparecerão aqui...")
	c.logsView.Disable()
	logsContent := container.NewBorder(
		widget.NewLabel("Logs de conexão"),
		container.NewGridWithColumns(3,
			widget.NewButton("Atualizar", c.refreshLogs),
			widget.NewButton("Limpar", c.clearLogs),
			widget.NewCheck("Rolagem automática", func(b bool) {}),
		),
		nil, nil, container.NewVScroll(c.logsView),
	)
	tabs := container.NewAppTabs(
		container.NewTabItem("Perfil", right),
		container.NewTabItem("Logs", logsContent),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	c.window.SetContent(container.NewHSplit(left, tabs))
}

func (c *controller) refresh() {
	profiles, err := c.store.List()
	if err != nil {
		c.error(err)
		return
	}
	c.profiles = profiles
	c.selected = -1
	c.list.UnselectAll()
	c.list.Refresh()
	c.details.SetText("Selecione um perfil à esquerda ou crie uma nova conexão.")
	c.message.SetText(fmt.Sprintf("%d perfil(is) salvo(s).", len(profiles)))
}

func (c *controller) current() (profile.Profile, bool) {
	if c.selected < 0 || c.selected >= len(c.profiles) {
		c.error(fmt.Errorf("selecione um perfil"))
		return profile.Profile{}, false
	}
	return c.profiles[c.selected], true
}

func (c *controller) showSelected() {
	p, ok := c.current()
	if !ok {
		return
	}
	c.details.SetText(fmt.Sprintf("Nome: %s\n\nGateway: %s\nIKE: versão %d · agressivo: %t\nUsuário XAuth: %s\nIdentidade PSK: %s\nVIP: %s\nRede remota: %s\n\nPropostas\nIKE: %s\nESP: %s\n\nDPD: %s / %s\nReautenticação: %s\n\nAs senhas não são exibidas. Elas permanecem cifradas no seu computador.", p.Name, p.RemoteAddress, p.Version, p.Aggressive, p.XAuthUsername, p.PSKIdentity, p.VirtualIP, p.RemoteTS, p.IKEProposal, p.ESPProposal, p.DPDDelay, p.DPDTimeout, p.ReauthTime))
	c.message.SetText("Perfil selecionado: " + p.Name)
}

func entry(value, hint string, password bool) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(value)
	e.SetPlaceHolder(hint)
	e.Password = password
	return e
}

func (c *controller) editProfile(index int) {
	isNew := index < 0
	p := profile.Defaults("")
	if !isNew {
		p = c.profiles[index]
	}
	name := entry(p.Name, "ex.: matriz", false)
	if !isNew {
		name.Disable()
	}
	remote := entry(p.RemoteAddress, "vpn.empresa.com", false)
	version := entry(fmt.Sprint(p.Version), "1 ou 2", false)
	user := entry(p.XAuthUsername, "usuário", false)
	password := entry("", "deixe vazio para manter", true)
	pskID := entry(p.PSKIdentity, "identidade PSK", false)
	psk := entry("", "deixe vazio para manter", true)
	vip := entry(p.VirtualIP, "0.0.0.0", false)
	remoteTS := entry(p.RemoteTS, "10.0.0.0/8,192.168.1.0/24", false)
	ike := entry(p.IKEProposal, "aes256-sha256-ecp384", false)
	esp := entry(p.ESPProposal, "aes256-sha256-ecp384", false)
	reauth := entry(p.ReauthTime, "43200s", false)
	dpdDelay := entry(p.DPDDelay, "30s", false)
	dpdTimeout := entry(p.DPDTimeout, "150s", false)
	life := entry(p.LifeTime, "43200s", false)
	rekey := entry(p.RekeyTime, "38880s", false)
	aggressive := widget.NewCheck("Usar modo agressivo (IKEv1)", nil)
	aggressive.SetChecked(p.Aggressive)
	pull := widget.NewCheck("Solicitar configuração ao servidor", nil)
	pull.SetChecked(p.Pull)

	form := widget.NewForm(
		widget.NewFormItem("Nome", name), widget.NewFormItem("Gateway", remote),
		widget.NewFormItem("Versão IKE", version), widget.NewFormItem("Usuário XAuth", user),
		widget.NewFormItem("Senha XAuth", password), widget.NewFormItem("Identidade PSK", pskID),
		widget.NewFormItem("Chave PSK", psk), widget.NewFormItem("VIP", vip),
		widget.NewFormItem("Redes remotas (vírgula)", remoteTS), widget.NewFormItem("Proposta IKE", ike),
		widget.NewFormItem("Proposta ESP", esp), widget.NewFormItem("Reautenticação", reauth),
		widget.NewFormItem("DPD intervalo", dpdDelay), widget.NewFormItem("DPD timeout", dpdTimeout),
		widget.NewFormItem("Vida do túnel", life), widget.NewFormItem("Rekey", rekey),
		widget.NewFormItem("Opções", container.NewVBox(aggressive, pull)),
	)
	content := container.NewBorder(widget.NewLabel("Senhas ficam cifradas e nunca são mostradas novamente."), nil, nil, nil, container.NewVScroll(form))
	d := dialog.NewCustomConfirm(map[bool]string{true: "Novo perfil", false: "Editar perfil"}[isNew], "Salvar", "Cancelar", content, func(save bool) {
		if !save {
			return
		}
		var parsedVersion int
		if _, err := fmt.Sscan(version.Text, &parsedVersion); err != nil {
			c.error(fmt.Errorf("versão IKE inválida"))
			return
		}
		p.Name, p.RemoteAddress, p.Version = strings.TrimSpace(name.Text), strings.TrimSpace(remote.Text), parsedVersion
		p.XAuthUsername, p.PSKIdentity = strings.TrimSpace(user.Text), strings.TrimSpace(pskID.Text)
		p.VirtualIP, p.RemoteTS, p.IKEProposal, p.ESPProposal = strings.TrimSpace(vip.Text), strings.TrimSpace(remoteTS.Text), strings.TrimSpace(ike.Text), strings.TrimSpace(esp.Text)
		p.ReauthTime, p.DPDDelay, p.DPDTimeout, p.LifeTime, p.RekeyTime = strings.TrimSpace(reauth.Text), strings.TrimSpace(dpdDelay.Text), strings.TrimSpace(dpdTimeout.Text), strings.TrimSpace(life.Text), strings.TrimSpace(rekey.Text)
		p.Aggressive, p.Pull = aggressive.Checked, pull.Checked
		if password.Text != "" {
			p.XAuthPassword = password.Text
		}
		if psk.Text != "" {
			p.PSK = psk.Text
		}
		if err := c.store.Put(p); err != nil {
			c.error(err)
			return
		}
		c.refresh()
		c.message.SetText("Perfil salvo. Use Conectar quando estiver pronto.")
	}, c.window)
	d.Resize(fyne.NewSize(650, 620))
	d.Show()
}

func (c *controller) deleteSelected() {
	p, ok := c.current()
	if !ok {
		return
	}
	dialog.ShowConfirm("Excluir perfil", "Excluir o perfil "+p.Name+"? As credenciais cifradas dele também serão removidas.", func(remove bool) {
		if !remove {
			return
		}
		if err := c.store.Delete(p.Name); err != nil {
			c.error(err)
			return
		}
		c.refresh()
	}, c.window)
}

func (c *controller) connectSelected() {
	p, ok := c.current()
	if !ok {
		return
	}
	c.message.SetText("Solicitando autorização e conectando " + p.Name + "…")
	if err := strongswan.EnsureGraphicalPrerequisites(); err != nil {
		c.error(err)
		return
	}
	if err := strongswan.NewGraphical().Connect(p); err != nil {
		c.error(err)
		return
	}
	c.message.SetText("Conectado: " + p.Name)
}

func (c *controller) disconnectSelected() {
	p, ok := c.current()
	if !ok {
		return
	}
	c.message.SetText("Desconectando " + p.Name + "…")
	if err := strongswan.EnsureGraphicalPrerequisites(); err != nil {
		c.error(err)
		return
	}
	if err := strongswan.NewGraphical().Disconnect(p); err != nil {
		c.error(err)
		return
	}
	c.message.SetText("Desconectado: " + p.Name)
}

func (c *controller) statusSelected() {
	p, ok := c.current()
	if !ok {
		return
	}
	if err := strongswan.EnsureGraphicalPrerequisites(); err != nil {
		c.error(err)
		return
	}
	status, err := strongswan.NewGraphical().Status(p.Name)
	if err != nil {
		c.error(err)
		return
	}
	dialog.ShowCustom("Estado: "+p.Name, "Fechar", container.NewVScroll(widget.NewLabel(status)), c.window)
}

func (c *controller) showLogs() {
	p, ok := c.current()
	if !ok {
		return
	}
	c.refreshLogsForProfile(p.Name)
}

func (c *controller) refreshLogs() {
	p, ok := c.current()
	if !ok {
		return
	}
	c.refreshLogsForProfile(p.Name)
}

func (c *controller) refreshLogsForProfile(name string) {
	if err := strongswan.EnsureGraphicalPrerequisites(); err != nil {
		c.error(err)
		return
	}
	status, err := strongswan.NewGraphical().Status(name)
	if err != nil {
		c.error(err)
		return
	}
	c.appendLog("=== Status " + name + " ===\n" + status + "\n")
}

func (c *controller) clearLogs() {
	c.logsView.SetText("")
}

func (c *controller) appendLog(text string) {
	current := c.logsView.Text
	c.logsView.SetText(current + text + "\n")
	c.logsView.CursorRow = len(strings.Split(c.logsView.Text, "\n"))
}

func (c *controller) error(err error) {
	c.message.SetText("Erro: " + err.Error())
	dialog.ShowError(err, c.window)
}
