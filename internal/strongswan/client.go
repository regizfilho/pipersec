// Package strongswan invokes swanctl with narrowly scoped, auditable commands.
package strongswan

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/codepiper/vpnctl/internal/profile"
)

type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type Client struct {
	Runner    Runner
	TempDir   string
	Elevator  []string
	Graphical bool
}

// New creates a client for command-line use, elevating through sudo.
func New() *Client { return &Client{Runner: ExecRunner{}, Elevator: []string{"sudo", "--"}} }

// NewGraphical creates a client for desktop applications. pkexec invokes the
// system's Polkit authentication dialog, so the user never has to use a shell
// to type a sudo password.
func NewGraphical() *Client {
	return &Client{Runner: ExecRunner{}, Elevator: []string{"pkexec"}, Graphical: true}
}

func (c *Client) execute(args ...string) ([]byte, error) {
	if len(c.Elevator) == 0 {
		return c.Runner.Run("swanctl", args...)
	}
	command := append(append([]string{}, c.Elevator[1:]...), "swanctl")
	command = append(command, args...)
	return c.Runner.Run(c.Elevator[0], command...)
}

func (c *Client) run(args ...string) error {
	output, err := c.execute(args...)
	if err != nil {
		return fmt.Errorf("swanctl %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func temporaryFile(dir, pattern, contents string) (string, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := f.WriteString(contents); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// Connect loads only this profile and initiates its child SA.
func (c *Client) Connect(p profile.Profile) error {
	conn, err := p.RenderConnection()
	if err != nil {
		return err
	}
	secrets, err := p.RenderSecrets()
	if err != nil {
		return err
	}
	connPath, err := temporaryFile(c.TempDir, "vpnctl-conn-*.conf", conn)
	if err != nil {
		return err
	}
	defer os.Remove(connPath)
	secretPath, err := temporaryFile(c.TempDir, "vpnctl-secret-*.conf", secrets)
	if err != nil {
		return err
	}
	defer os.Remove(secretPath)
	if c.Graphical {
		helper, err := os.Executable()
		if err != nil {
			return fmt.Errorf("localizar PiperSec: %w", err)
		}
		output, err := c.Runner.Run("pkexec", helper, "privileged-connect", connPath, secretPath, p.Name)
		if err != nil {
			return fmt.Errorf("conectar %s: %w\n%s", p.Name, err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := c.run("--load-creds", "--file", secretPath); err != nil {
		return err
	}
	// Load credentials first: the daemon resolves PSK/XAuth references while
	// processing the connection configuration.
	if err := c.run("--load-conns", "--file", connPath); err != nil {
		return err
	}
	return c.run("--initiate", "--ike", p.Name)
}

// Disconnect terminates the active IKE SA. swanctl deliberately has no
// per-connection unload operation, so its loaded definition remains available
// for a subsequent reconnect without touching unrelated system profiles.
func (c *Client) Disconnect(p profile.Profile) error {
	if err := p.Validate(false); err != nil {
		return err
	}
	if c.Graphical {
		helper, err := os.Executable()
		if err != nil {
			return fmt.Errorf("localizar PiperSec: %w", err)
		}
		output, err := c.Runner.Run("pkexec", helper, "privileged-disconnect", p.Name)
		if err != nil {
			return fmt.Errorf("desconectar %s: %w\n%s", p.Name, err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	return c.run("--terminate", "--ike", p.Name)
}

func (c *Client) Status(name string) (string, error) {
	output, err := c.execute("--list-sas", "--ike", name)
	if err != nil {
		return "", fmt.Errorf("consultar estado: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// EnsureInstalled checks the local prerequisite without making changes.
func EnsureInstalled() error {
	if _, err := exec.LookPath("swanctl"); err != nil {
		return fmt.Errorf("swanctl não encontrado: instale o strongSwan (ex.: sudo apt install strongswan-swanctl)")
	}
	return nil
}

// EnsureGraphicalPrerequisites verifies the Polkit helper used by the GUI.
func EnsureGraphicalPrerequisites() error {
	if err := EnsureInstalled(); err != nil {
		return err
	}
	if _, err := exec.LookPath("pkexec"); err != nil {
		return fmt.Errorf("pkexec não encontrado: instale o policykit-1 para autorizar conexões pela interface gráfica")
	}
	return nil
}
