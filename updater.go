package autoupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/rogpeppe/go-internal/semver"
)

type Updater struct {
	Repo   string
	Client Client
	Dir    string
	PkgDir string

	Options Options

	currentVersion string
}

func (updater *Updater) DoUpdate(ctx context.Context) error {
	if updater.currentVersion == "" {
		var err error
		updater.currentVersion, err = updater.ReadCurrentVersion(ctx)
		if err != nil {
			return err
		}
	}

	updateList, err := updater.Client.Read(ctx, updater.Repo)
	if err != nil {
		return err
	}

	versionList, pkgList, err := selectVersions(updateList, updater.currentVersion)
	if err != nil {
		return err
	}

	for idx, version := range versionList {
		err = updater.Update(ctx, version, pkgList[idx])
		if err != nil {
			return err
		}
	}
	return nil
}

func (updater *Updater) ReadVersions(ctx context.Context) ([]string, error) {
	fis, err := os.ReadDir(updater.PkgDir)
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
	versionList, err := updater.ReadVersions(ctx)
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
	versionDir := filepath.Join(updater.PkgDir, version)
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
	if err := Apply(targetDir, updater.Dir, updater.Options); err != nil {
		return errors.New("尝试更新文件失败: " + err.Error())
	}
	return nil
}

func selectVersions(updateList []AvailableUpdate, currentVersion string) ([]string, []PackageInfo, error) {
	list, err := selectUpdateList(updateList, currentVersion)
  if err != nil {
    return nil, nil, err
  }

	arch := runtime.GOOS + "_" + runtime.GOARCH

	var versionResults []string
	var pkgResults []PackageInfo

	for _, pkg := range list {
		for _, info := range pkg.List {
			if info.Arch == arch {
				versionResults = append(versionResults, pkg.Version)
				pkgResults = append(pkgResults, info)
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
