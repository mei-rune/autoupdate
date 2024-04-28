package autoupdate

import (
	"context"
	"net/http"
	"os"
)

type Options struct {
	BaseURL string `json:"base_url"`
	Repo    string `json:"repo"`

	RootDir   string `json:"root_dir"`
	UpdateDir string `json:"update_dir"`
	BackupDir string `json:"backup_dir"`
	OsArch string `json:"os_arch"`

	SigningAlgorithm string `json:"signing_algorithm"`
	PublicKeyFile    string `json:"public_key_file"`

	HTTP *http.Client `json:"-"`
}

type AvailableUpdate struct {
	Version string        `json:"version"`
	List    []PackageInfo `json:"list"`
}

type PackageInfo struct {
	// 包含 os 和 cpu
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	URLPath  string `json:"path"`
	SUM      string `json:"sum"`
}

type Client interface {
	Read(ctx context.Context, repo string) ([]AvailableUpdate, error)

	DownloadKeyFile(ctx context.Context, repo string) (string, error)

	RetrievePackage(ctx context.Context, info PackageInfo, dir string) (string, error)
}

func ReadConfigFrom(opts *Options, props map[string]string, prefix string) error {
	if s, ok := props[prefix+"update_url"]; ok {
		opts.BaseURL = os.Expand(s, func(key string) string {
			if value, ok := props[key]; ok {
				return value
			}
			return "${" + key + "}"
		})
	}
	if s, ok := props[prefix+"signing_algorithm"]; ok {
		opts.SigningAlgorithm = s
	}
	if s, ok := props[prefix+"public_key_file"]; ok {
		opts.PublicKeyFile = s
	}
	if s, ok := props[prefix+"repo"]; ok {
		opts.Repo = s
	}
	if s, ok := props[prefix+"os_arch"]; ok {
		opts.OsArch = s
	}
	if s, ok := props[prefix+"root_dir"]; ok {
		opts.RootDir = s
	}
	if s, ok := props[prefix+"update_dir"]; ok {
		opts.UpdateDir = s
	}
	if s, ok := props[prefix+"backup_dir"]; ok {
		opts.BackupDir = s
	}
	return nil
}
