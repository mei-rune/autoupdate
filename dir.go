package autoupdate

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

func skipByName(name string) bool {
	return strings.HasPrefix(name, ".") ||
		strings.HasPrefix(name, "ignore") ||
		name == "tmp"
}

func ReadRepoDir(dir fs.FS, pa string) ([]string, error) {
	list, err := fs.ReadDir(dir, filepath.ToSlash(pa))
	if err != nil {
		return nil, err
	}

	var results []string
	for i, n := 0, len(list); i < n; i++ {
		if skipByName(list[i].Name()) {
			continue
		}
		if list[i].IsDir() {
			results = append(results, list[i].Name())
		}
	}
	return results, nil
}

func ReadRepo(dir fs.FS, pa string, repoFn func([]AvailableUpdate) error, pkgFn func([]PackageInfo) error) error {
	list, err := fs.ReadDir(dir, filepath.ToSlash(pa))
	if err != nil {
		return err
	}

	pkgs, err := readPackageDir(dir, pa, list)
	if err != nil {
		return err
	}
	if len(pkgs) > 0 {
		if pkgFn == nil {
			return nil
		}
		return pkgFn(pkgs)
	}

	for i, n := 0, len(list); i < n; i++ {
		if skipByName(list[i].Name()) {
			continue
		}

		if list[i].IsDir() {
			results, err := readRepoPackages(dir, pa, list)
			if err != nil {
				return err
			}
			if repoFn == nil {
				return nil
			}
			return repoFn(results)
		}
	}
	return errors.New("dir '" + pa + "' isnot repo or package dir")
}

func ReadRepoPackages(dir fs.FS, pa string) ([]AvailableUpdate, error) {
	list, err := fs.ReadDir(dir, filepath.ToSlash(pa))
	if err != nil {
		return nil, err
	}
	return readRepoPackages(dir, pa, list)
}

func readRepoPackages(dir fs.FS, pa string, list []fs.DirEntry) ([]AvailableUpdate, error) {
	var results []AvailableUpdate
	for i, n := 0, len(list); i < n; i++ {
		if skipByName(list[i].Name()) {
			continue
		}
		if list[i].IsDir() {
			pkgs, err := ReadPackageDir(dir, filepath.Join(pa, list[i].Name()))
			if err != nil {
				return nil, err
			}
			results = append(results, AvailableUpdate{
				Version: list[i].Name(),
				List:    pkgs,
			})
		}
	}
	return results, nil
}

func ReadPackageDir(dir fs.FS, pa string) ([]PackageInfo, error) {
	list, err := fs.ReadDir(dir, filepath.ToSlash(pa))
	if err != nil {
		return nil, err
	}
	return readPackageDir(dir, pa, list)
}

func readPackageDir(dir fs.FS, pa string, list []fs.DirEntry) ([]PackageInfo, error) {
	var results []PackageInfo
	for i, n := 0, len(list); i < n; i++ {
		if skipByName(list[i].Name()) {
			continue
		}

		if list[i].IsDir() {
			continue
		}

		ext := filepath.Ext(list[i].Name())
		if ext == ".sum" {
			continue
		}
		if ext != ".gz" && ext != ".zip" {
			continue
		}

		info, err := ReadPackageInfo(dir, pa, list[i].Name())
		if err != nil {
			return nil, err
		}

		results = append(results, info)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Filename < results[j].Filename
	})
	return results, nil
}

func ReadPackageInfo(dir fs.FS, pa, name string) (PackageInfo, error) {
	u := filepath.ToSlash(filepath.Join(pa, name))
	sum, err := fs.ReadFile(dir, u+".sum")
	if err != nil {
		return PackageInfo{}, err
	}

	arch := name
	idx := strings.IndexRune(arch, '@')
	if idx >= 0 {
		arch = arch[idx+1:]
	}
	idx = strings.IndexRune(arch, '.')
	if idx >= 0 {
		arch = arch[:idx]
	}
	return PackageInfo{
		Arch:     arch,
		Filename: name,
		URLPath:  u,
		SUM:      string(sum),
	}, nil
}
