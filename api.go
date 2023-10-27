package autoupdate

import "context"

type Config struct {
	BaseURL string
	Repo    string
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

type Updater struct {
}
