package autoupdate

import (
	"context"
	"errors"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"golang.org/x/mod/semver"
)

func NewUpdater(opts Options) (*Updater, error) {
	if opts.BaseURL == "" {
		return nil, errors.New("'base_url' 不可为空")
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, errors.New("'base_url' 格式不正确: " + err.Error())
	}
	client := &HTTPClient{
		BaseURL: u,
		Client:  opts.HTTP,
	}

	err = client.LoadSigningMethod(opts.SigningAlgorithm, opts.PublicKeyFile)
	if err != nil {
		return nil, errors.New("加载签名失败: " + err.Error())
	}

	if opts.Repo == "" {
		return nil, errors.New("'repo' 不可为空")
	}
	if opts.RootDir == "" {
		return nil, errors.New("'root_dir' 不可为空")
	}

	if opts.UpdateDir == "" {
		opts.UpdateDir = filepath.Join(opts.RootDir, "patchs")
	}

	if opts.BackupDir == "" {
		opts.BackupDir = filepath.Join(opts.RootDir, "softbase")
	}

	return &Updater{
		Client:  client,
		Options: opts,
	}, nil

	// updater := &Updater{
	// 	Client:  client,
	// 	Options: opts,
	// }

	// _, err = updater.ReadCurrentVersion(context.Background())
	// if err != nil {
	// 	return nil, err
	// }
	// return updater, nil
}

type Updater struct {
	Client Client

	Options Options

	currentVersion string
}

func (updater *Updater) GetArch() string {
	return getArch()
}

func (updater *Updater) Test(ctx context.Context) error {
	_, err := updater.Client.Read(ctx, updater.Options.Repo)
	return err
}

func (updater *Updater) DoUpdate(ctx context.Context) (bool, error) {
	if updater.currentVersion == "" {
		var err error
		updater.currentVersion, err = updater.ReadCurrentVersion(ctx)
		if err != nil {
			return false, err
		}
	}

	updateList, err := updater.Client.Read(ctx, updater.Options.Repo)
	if err != nil {
		return false, err
	}

	versionList, pkgList, err := selectVersions(updateList, updater.currentVersion)
	if err != nil {
		return false, err
	}
	if len(versionList) == 0 {
		return false, nil
	}

	currentVersion := updater.currentVersion

	hasUpdateOk := false
	for idx, version := range versionList {
		log.Println("准备从 '" + currentVersion + "' 升级到 '" + version + "'")
		err = updater.Update(ctx, version, pkgList[idx])
		if err != nil {
			log.Println("从 '"+currentVersion+"' 升级到 '"+version+"' 失败,", err)
			return hasUpdateOk, errors.New("从 '" + currentVersion + "' 升级到 '" + version + "' 失败, " + err.Error())
		}
		log.Println("成功升级到 '" + version + "'")
		hasUpdateOk = true
		currentVersion = version
		updater.currentVersion = version
	}
	return hasUpdateOk, nil
}

func (updater *Updater) GetCurrentVersion(ctx context.Context) string {
	return updater.currentVersion
}

func (updater *Updater) ReadLocalVersions(ctx context.Context) ([]string, error) {
	fis, err := os.ReadDir(updater.Options.UpdateDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return nil, nil
	}

	var versionList []string
	for _, fi := range fis {
		version := fi.Name()
		if semver.IsValid(version) {
			versionList = append(versionList, version)
		}
	}
	return versionList, nil
}

func (updater *Updater) ReadCurrentVersion(ctx context.Context) (string, error) {
	versionList, err := updater.ReadLocalVersions(ctx)
	if err != nil {
		return "", errors.New("读当前版本号时，" + err.Error())
	}
	switch len(versionList) {
	case 0:
		return "", nil
	case 1:
		return versionList[0], nil
	}

	maxVersion := versionList[0]
	for _, version := range versionList[1:] {
		maxVersion = semver.Max(maxVersion, version)
	}
	return maxVersion, nil
}

func (updater *Updater) Update(ctx context.Context, version string, info PackageInfo) error {
	versionDir := filepath.Join(updater.Options.UpdateDir, version)
	if err := os.MkdirAll(versionDir, 0775); err != nil {
		return errors.New("尝试新建目录 '" + versionDir + "' 失败: " + err.Error())
	}

	filename, err := updater.Client.RetrievePackage(ctx, info, versionDir)
	if err != nil {
		return errors.New("下载更新包出错: " + err.Error())
	}

	targetDir := filepath.Join(versionDir, "pkg")
	if err := os.MkdirAll(targetDir, 0775); err != nil {
		return errors.New("尝试新建目录 '" + targetDir + "' 失败: " + err.Error())
	}
	if err := Uncompress(filename, targetDir); err != nil {
		return errors.New("尝试解压安装包 '" + filename + "' 失败: " + err.Error())
	}
	if err := Apply(targetDir, updater.Options.RootDir, updater.Options); err != nil {
		return errors.New("尝试更新文件失败: " + err.Error())
	}
	return nil
}

func getArch() string {
	return runtime.GOOS + "_" + runtime.GOARCH
}

func getNoArch() string {
	return runtime.GOOS + "_noarch"
}

func selectVersions(updateList []AvailableUpdate, currentVersion string) ([]string, []PackageInfo, error) {
	list, err := selectUpdateList(updateList, currentVersion)
	if err != nil {
		return nil, nil, err
	}

	var versionResults []string
	var pkgResults []PackageInfo

	for _, pkg := range list {
		for _, arch := range []string{
			getArch(),
			getNoArch(),
			"noarch",
		} {
			found := false
			for _, info := range pkg.List {
				if info.Arch == arch {
					found = true
					versionResults = append(versionResults, pkg.Version)
					pkgResults = append(pkgResults, info)
					break
				}
			}
			if found {
				break
			}
		}
	}
	return versionResults, pkgResults, nil
}

func selectUpdateList(updateList []AvailableUpdate, currentVersion string) ([]AvailableUpdate, error) {
	sort.Slice(updateList, func(i, j int) bool {
		return semver.Compare(updateList[i].Version, updateList[j].Version) < 0
	})

	nextIndex := -1
	if currentVersion != "" {
		for idx := range updateList {
			if updateList[idx].Version == currentVersion {
				nextIndex = idx + 1
				break
			}
		}
		if nextIndex < 0 {
			for idx := range updateList {
				if semver.Compare(updateList[idx].Version, currentVersion) >= 0 {
					nextIndex = idx + 1
					break
				}
			}
		}
	}

	if nextIndex < 0 {
		nextIndex = 0
	}

	if len(updateList) > nextIndex {
		return updateList[nextIndex:], nil
	}
	return nil, nil
}
