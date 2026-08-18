// vpnctl manages encrypted strongSwan/swanctl connection profiles.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/codepiper/vpnctl/internal/profile"
	"github.com/codepiper/vpnctl/internal/store"
	"github.com/codepiper/vpnctl/internal/strongswan"
)

func usage() {
	fmt.Fprint(os.Stderr, `vpnctl — gerenciador de perfis IPsec/strongSwan

Uso:
  vpnctl [--config-dir DIR] <comando> [opções]

Comandos:
  add <nome>             cria um perfil (credenciais exigidas)
  edit <nome>            altera campos de um perfil existente
  list                   lista os perfis salvos
  show <nome>            exibe um perfil, sem segredos
  delete <nome>          remove um perfil local
  render <nome>          imprime a configuração swanctl, sem segredos
  connect <nome>         carrega e inicia a VPN com sudo swanctl
  disconnect <nome>      encerra e descarrega a VPN
  status <nome>          mostra os SAs ativos
  import-example         cria um perfil IKEv1/XAuth genérico, sem segredos

Exemplo:
  vpnctl add minha-vpn --remote vpn.exemplo.com --user meu.usuario --password 'minha-senha' --psk-id vpn.exemplo.com --psk 'minha-chave'

Use "vpnctl <comando> --help" para as opções do comando.
`)
}

func main() {
	args := os.Args[1:]
	base := ""
	if len(args) >= 2 && args[0] == "--config-dir" {
		base = args[1]
		args = args[2:]
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}
	var s *store.Store
	if base != "" {
		s = store.New(base)
	} else {
		var err error
		s, err = store.Default()
		fail(err)
	}
	var err error
	switch args[0] {
	case "add":
		err = add(s, args[1:])
	case "edit":
		err = edit(s, args[1:])
	case "list":
		err = list(s, args[1:])
	case "show":
		err = show(s, args[1:])
	case "delete":
		err = deleteProfile(s, args[1:])
	case "render":
		err = render(s, args[1:])
	case "connect":
		err = connect(s, args[1:])
	case "disconnect":
		err = disconnect(s, args[1:])
	case "status":
		err = status(s, args[1:])
	case "import-example":
		err = importExample(s, args[1:])
	case "gui-list":
		err = guiList(s, args[1:])
	case "gui-save":
		err = guiSave(s, args[1:])
	case "gui-connect":
		err = guiConnect(s, args[1:])
	case "gui-disconnect":
		err = guiDisconnect(s, args[1:])
	case "privileged-connect":
		err = privilegedConnect(args[1:])
	case "privileged-disconnect":
		err = privilegedDisconnect(args[1:])
	case "privileged-status":
		err = privilegedStatus(args[1:])
	case "privileged-sas":
		err = privilegedSAS(args[1:])
	case "privileged-logs":
		err = privilegedLogs(args[1:])
	case "gui-status":
		err = guiStatus(s, args[1:])
	case "gui-sas":
		err = guiSAS(s, args[1:])
	case "gui-logs":
		err = guiLogs(args[1:])
	default:
		usage()
		os.Exit(2)
	}
	fail(err)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}
func requireName(args []string, action string) (string, error) {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return "", fmt.Errorf("uso: vpnctl %s <nome>", action)
	}
	return args[0], nil
}

func defineProfileFlags(fs *flag.FlagSet, p *profile.Profile) {
	fs.StringVar(&p.RemoteAddress, "remote", p.RemoteAddress, "IP ou DNS do gateway VPN")
	fs.IntVar(&p.Version, "version", p.Version, "versão IKE: 1 ou 2")
	fs.BoolVar(&p.Aggressive, "aggressive", p.Aggressive, "modo agressivo IKEv1")
	fs.StringVar(&p.VirtualIP, "vip", p.VirtualIP, "VIP solicitado, ex. 0.0.0.0")
	fs.BoolVar(&p.Pull, "pull", p.Pull, "solicitar configuração ao servidor")
	fs.StringVar(&p.IKEProposal, "ike-proposal", p.IKEProposal, "proposta IKE")
	fs.StringVar(&p.ESPProposal, "esp-proposal", p.ESPProposal, "proposta ESP")
	fs.StringVar(&p.ReauthTime, "reauth-time", p.ReauthTime, "tempo de reautenticação")
	fs.StringVar(&p.DPDDelay, "dpd-delay", p.DPDDelay, "intervalo DPD")
	fs.StringVar(&p.DPDTimeout, "dpd-timeout", p.DPDTimeout, "timeout DPD")
	fs.StringVar(&p.XAuthUsername, "user", p.XAuthUsername, "usuário XAuth")
	fs.StringVar(&p.XAuthPassword, "password", p.XAuthPassword, "senha XAuth")
	fs.StringVar(&p.PSKIdentity, "psk-id", p.PSKIdentity, "identidade associada à PSK")
	fs.StringVar(&p.PSK, "psk", p.PSK, "chave pré-compartilhada")
	fs.StringVar(&p.RemoteTS, "remote-ts", p.RemoteTS, "redes remotas (separadas por vírgula, ex.: 10.0.0.0/8,192.168.1.0/24)")
	fs.StringVar(&p.LifeTime, "life-time", p.LifeTime, "vida do child SA")
	fs.StringVar(&p.RekeyTime, "rekey-time", p.RekeyTime, "tempo de rekey")
}

func add(s *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("uso: vpnctl add <nome> [opções]")
	}
	p := profile.Defaults(args[0])
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defineProfileFlags(fs, &p)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("argumentos extras inválidos")
	}
	if err := p.Validate(true); err != nil {
		return err
	}
	return s.Put(p)
}
func edit(s *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("uso: vpnctl edit <nome> [opções]")
	}
	p, err := s.Get(args[0])
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defineProfileFlags(fs, &p)
	if err = fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("argumentos extras inválidos")
	}
	if err := p.Validate(true); err != nil {
		return err
	}
	return s.Put(p)
}
func list(s *store.Store, args []string) error {
	if len(args) != 0 {
		return errors.New("list não recebe argumentos")
	}
	items, err := s.List()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("Nenhum perfil salvo.")
		return nil
	}
	fmt.Printf("%-20s %-28s %-18s %s\n", "NOME", "GATEWAY", "USUÁRIO", "IKE")
	for _, p := range items {
		fmt.Printf("%-20s %-28s %-18s v%d\n", p.Name, p.RemoteAddress, p.XAuthUsername, p.Version)
	}
	return nil
}
func show(s *store.Store, args []string) error {
	name, err := requireName(args, "show")
	if err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	fmt.Printf("Nome: %s\nGateway: %s\nIKE: v%d (agressivo: %t)\nUsuário XAuth: %s\nIdentidade PSK: %s\nVIP: %s\nPropostas: %s / %s\nRedes remotas: %s\nSegredos: armazenados cifrados (ocultos)\n", p.Name, p.RemoteAddress, p.Version, p.Aggressive, p.XAuthUsername, p.PSKIdentity, p.VirtualIP, p.IKEProposal, p.ESPProposal, p.RemoteTS)
	return nil
}
func deleteProfile(s *store.Store, args []string) error {
	name, err := requireName(args, "delete")
	if err != nil {
		return err
	}
	return s.Delete(name)
}
func render(s *store.Store, args []string) error {
	name, err := requireName(args, "render")
	if err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	out, err := p.RenderConnection()
	if err == nil {
		fmt.Print(out)
	}
	return err
}
func connect(s *store.Store, args []string) error {
	name, err := requireName(args, "connect")
	if err != nil {
		return err
	}
	if err = strongswan.EnsureInstalled(); err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	return strongswan.New().Connect(p)
}
func disconnect(s *store.Store, args []string) error {
	name, err := requireName(args, "disconnect")
	if err != nil {
		return err
	}
	if err = strongswan.EnsureInstalled(); err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	return strongswan.New().Disconnect(p)
}
func status(s *store.Store, args []string) error {
	name, err := requireName(args, "status")
	if err != nil {
		return err
	}
	if err = strongswan.EnsureInstalled(); err != nil {
		return err
	}
	if _, err = s.Get(name); err != nil {
		return err
	}
	out, err := strongswan.New().Status(name)
	if err == nil {
		fmt.Print(out)
	}
	return err
}
func importExample(s *store.Store, args []string) error {
	if len(args) != 0 {
		return errors.New("import-example não recebe argumentos")
	}
	p := profile.Defaults("vpn-exemplo")
	p.RemoteAddress = "vpn.exemplo.com"
	p.XAuthUsername = "meu.usuario"
	p.PSKIdentity = "vpn.exemplo.com"
	return s.Put(p)
}

// gui-list is a private bridge for the native desktop shell. It never emits
// credentials, only the public profile fields needed to render the UI.
func guiList(s *store.Store, args []string) error {
	if len(args) != 0 {
		return errors.New("gui-list não recebe argumentos")
	}
	items, err := s.List()
	if err != nil {
		return err
	}
	for i := range items {
		items[i].XAuthPassword = ""
		items[i].PSK = ""
	}
	return json.NewEncoder(os.Stdout).Encode(items)
}

// gui-save reads profile data from standard input so password values never
// appear in the desktop process list.
func guiSave(s *store.Store, args []string) error {
	if len(args) != 0 {
		return errors.New("gui-save não recebe argumentos")
	}
	var p profile.Profile
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return fmt.Errorf("perfil gráfico inválido: %w", err)
	}
	if old, err := s.Get(p.Name); err == nil {
		if p.XAuthPassword == "" {
			p.XAuthPassword = old.XAuthPassword
		}
		if p.PSK == "" {
			p.PSK = old.PSK
		}
	}
	return s.Put(p)
}
func guiConnect(s *store.Store, args []string) error {
	name, err := requireName(args, "gui-connect")
	if err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	if err = strongswan.EnsureGraphicalPrerequisites(); err != nil {
		return err
	}
	return strongswan.NewGraphical().Connect(p)
}
func guiDisconnect(s *store.Store, args []string) error {
	name, err := requireName(args, "gui-disconnect")
	if err != nil {
		return err
	}
	p, err := s.Get(name)
	if err != nil {
		return err
	}
	if err = strongswan.EnsureGraphicalPrerequisites(); err != nil {
		return err
	}
	return strongswan.NewGraphical().Disconnect(p)
}

// These helpers are called once through pkexec by the desktop application.
// They deliberately accept generated temporary config paths, avoiding a root
// read of the user's encrypted profile store.
func privilegedConnect(args []string) error {
	if len(args) != 3 {
		return errors.New("uso interno inválido: privileged-connect")
	}
	connection, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("ler configuração temporária: %w", err)
	}
	secrets, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("ler credenciais temporárias: %w", err)
	}
	// Ubuntu's strongSwan service loads /etc/swanctl/conf.d/*.conf.  Put a
	// root-only, short-lived snippet there so that swanctl uses its native
	// configuration directory instead of the unreliable custom --file path.
	const configDir = "/etc/swanctl/conf.d"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("preparar diretório do strongSwan: %w", err)
	}
	config, err := os.CreateTemp(configDir, "pipersec-runtime-*.conf")
	if err != nil {
		return fmt.Errorf("criar configuração temporária: %w", err)
	}
	configPath := config.Name()
	defer os.Remove(configPath)
	if err := config.Chmod(0600); err != nil {
		config.Close()
		return fmt.Errorf("proteger configuração temporária: %w", err)
	}
	if _, err := config.Write(append(append(connection, '\n'), secrets...)); err != nil {
		config.Close()
		return fmt.Errorf("gravar configuração temporária: %w", err)
	}
	if err := config.Close(); err != nil {
		return fmt.Errorf("fechar configuração temporária: %w", err)
	}
	loadOutput, err := exec.Command("swanctl", "--load-all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("carregar perfil no strongSwan: %w\n%s", err, cleanSwanctlOutput(loadOutput))
	}
	// swanctl 6.0 does not support filtering --list-conns by IKE name.
	// List all loaded profiles and verify ours in-process instead.
	loaded, err := exec.Command("swanctl", "--list-conns").CombinedOutput()
	if err != nil {
		return fmt.Errorf("verificar perfil carregado: %w\n%s", err, cleanSwanctlOutput(loaded))
	}
	if !strings.Contains(string(loaded), args[2]) {
		return fmt.Errorf("o strongSwan não carregou o perfil %q. Resultado do carregamento:\n%s", args[2], cleanSwanctlOutput(loadOutput))
	}
	out, err := exec.Command("swanctl", "--initiate", "--ike", args[2]).CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl initiate: %w\n%s", err, cleanSwanctlOutput(out))
	}
	return nil
}

func cleanSwanctlOutput(out []byte) string {
	var relevant []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "plugin '") ||
			strings.HasPrefix(line, "found and no plugin file available") ||
			strings.Contains(line, "plugin_create") ||
			strings.HasPrefix(line, "agent plugin requires") {
			continue
		}
		relevant = append(relevant, line)
	}
	if len(relevant) == 0 {
		return "nenhuma mensagem adicional fornecida pelo strongSwan"
	}
	return strings.Join(relevant, "\n")
}
func privilegedDisconnect(args []string) error {
	if len(args) != 1 {
		return errors.New("uso interno inválido: privileged-disconnect")
	}
	out, err := exec.Command("swanctl", "--terminate", "--ike", args[0]).CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl terminate: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// guiStatus reports the current IKE SA state for a profile through pkexec,
// so the desktop GUI never has to invoke sudo from a terminal-less session.
func guiStatus(s *store.Store, args []string) error {
	name, err := requireName(args, "gui-status")
	if err != nil {
		return err
	}
	if _, err := s.Get(name); err != nil {
		return err
	}
	return runPrivilegedHelper("privileged-status", name)
}

// guiSAS returns structured CHILD_SA counters for a profile, enabling the
// GUI to render live input/output rates.
func guiSAS(s *store.Store, args []string) error {
	name, err := requireName(args, "gui-sas")
	if err != nil {
		return err
	}
	if _, err := s.Get(name); err != nil {
		return err
	}
	return runPrivilegedHelper("privileged-sas", name)
}

// guiLogs returns the recent strongSwan service logs through pkexec.
func guiLogs(args []string) error {
	if len(args) != 0 {
		return errors.New("gui-logs não recebe argumentos")
	}
	return runPrivilegedHelper("privileged-logs")
}

// runPrivilegedHelper re-invokes this binary through pkexec with one of the
// privileged-* subcommands. Only local active users granted by the polkit
// rule can run it, and it exposes just the narrow swanctl operations below.
func runPrivilegedHelper(sub string, args ...string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("localizar PiperSec: %w", err)
	}
	full := append([]string{self, sub}, args...)
	out, err := exec.Command("pkexec", full...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", sub, err, strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}

// privileged-status prints the human-readable SA list for one IKE name.
func privilegedStatus(args []string) error {
	if len(args) != 1 {
		return errors.New("uso interno inválido: privileged-status")
	}
	out, err := exec.Command("swanctl", "--list-sas", "--ike", args[0]).CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl status: %w\n%s", err, cleanSwanctlOutput(out))
	}
	fmt.Print(string(out))
	return nil
}

// privileged-sas prints structured CHILD_SA counters parsed from swanctl --raw.
func privilegedSAS(args []string) error {
	if len(args) != 1 {
		return errors.New("uso interno inválido: privileged-sas")
	}
	out, err := exec.Command("swanctl", "--list-sas", "--ike", args[0], "--raw").CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl sas: %w\n%s", err, cleanSwanctlOutput(out))
	}
	fmt.Println(strongswan.ParseSASRaw(string(out)).JSON())
	return nil
}

// privileged-logs prints the tail of the strongSwan service journal.
func privilegedLogs(args []string) error {
	if len(args) != 0 {
		return errors.New("uso interno inválido: privileged-logs")
	}
	out, err := exec.Command("journalctl", "-u", "strongswan.service", "--no-pager", "-n", "200", "--output=short").CombinedOutput()
	if err != nil {
		return fmt.Errorf("journalctl strongswan: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}
