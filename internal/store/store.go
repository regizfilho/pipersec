// Package store persists profiles encrypted at rest using AES-256-GCM.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/codepiper/vpnctl/internal/profile"
)

const appDirName = "vpnctl"

type encryptedFile struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
type data struct {
	Version  int                        `json:"version"`
	Profiles map[string]profile.Profile `json:"profiles"`
}

type Store struct{ dir, keyPath, dataPath string }

func New(baseDir string) *Store {
	return &Store{dir: filepath.Join(baseDir, appDirName), keyPath: filepath.Join(baseDir, appDirName, "master.key"), dataPath: filepath.Join(baseDir, appDirName, "profiles.enc")}
}

func Default() (*Store, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("diretório de configuração: %w", err)
	}
	return New(base), nil
}

func (s *Store) ensureKey() ([]byte, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, err
	}
	_ = os.Chmod(s.dir, 0700)
	key, err := os.ReadFile(s.keyPath)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("master.key inválida; restaure um backup ou remova os arquivos vpnctl")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := atomicWrite(s.keyPath, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Store) Load() (map[string]profile.Profile, error) {
	key, err := s.ensureKey()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]profile.Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var sealed encryptedFile
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return nil, fmt.Errorf("arquivo de perfis inválido: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("não foi possível decifrar os perfis: chave ou arquivo inválido")
	}
	var d data
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, err
	}
	if d.Profiles == nil {
		d.Profiles = map[string]profile.Profile{}
	}
	return d.Profiles, nil
}

func (s *Store) Save(profiles map[string]profile.Profile) error {
	key, err := s.ensureKey()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(data{Version: 1, Profiles: profiles})
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := encryptedFile{Version: 1, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, nil))}
	raw, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.dataPath, raw, 0600)
}

func (s *Store) Put(p profile.Profile) error {
	// Secrets may be intentionally absent from a drafted/imported profile; they
	// are mandatory only at connection time.
	if err := p.Validate(false); err != nil {
		return err
	}
	all, err := s.Load()
	if err != nil {
		return err
	}
	all[p.Name] = p
	return s.Save(all)
}
func (s *Store) Get(name string) (profile.Profile, error) {
	all, err := s.Load()
	if err != nil {
		return profile.Profile{}, err
	}
	p, ok := all[name]
	if !ok {
		return profile.Profile{}, fmt.Errorf("perfil %q não encontrado", name)
	}
	return p, nil
}
func (s *Store) Delete(name string) error {
	all, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := all[name]; !ok {
		return fmt.Errorf("perfil %q não encontrado", name)
	}
	delete(all, name)
	return s.Save(all)
}
func (s *Store) List() ([]profile.Profile, error) {
	all, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := make([]profile.Profile, 0, len(all))
	for _, p := range all {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
