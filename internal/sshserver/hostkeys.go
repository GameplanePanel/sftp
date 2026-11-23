package sshserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LoadHostKeys reads host keys from path, which is one private key file or a
// directory of them. In a directory it takes every regular file except
// hidden names (Kubernetes Secret bookkeeping such as ..data) and public
// keys (*.pub). Symlinks are followed, so a mounted Secret works. Any file
// that does not parse is an error, and so is a directory with no keys.
func LoadHostKeys(path string) ([]ssh.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("host key %s: %w", path, err)
	}
	files := []string{path}
	if info.IsDir() {
		files, err = hostKeyFiles(path)
		if err != nil {
			return nil, err
		}
	}
	signers := make([]ssh.Signer, 0, len(files))
	for _, f := range files {
		data, err := readKeyFile(f)
		if err != nil {
			return nil, fmt.Errorf("read host key %s: %w", f, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", f, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

func hostKeyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read host key dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".pub") {
			continue
		}
		full := filepath.Join(dir, name)
		fi, err := os.Stat(full)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, full)
	}
	if len(files) == 0 {
		return nil, errors.New("no host keys found in " + dir)
	}
	return files, nil
}

// readKeyFile reads one key file through os.Root, so the read stays inside the
// file's directory: a path cannot leave it with ".." or an escaping symlink.
// A mounted Secret's links stay inside its directory, so they still work.
func readKeyFile(path string) ([]byte, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}
