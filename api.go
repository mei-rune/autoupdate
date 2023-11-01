package autoupdate

import (
	"context"
	"net/http"
)

type Options struct {
	BaseURL string `json:"base_url"`
	Repo    string `json:"repo"`

	RootDir   string `json:"root_dir"`
	UpdateDir string `json:"update_dir"`
	BackupDir string `json:"backup_dir"`

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

	RetrievePackage(ctx context.Context, info PackageInfo, dir string) (string, error)
}
