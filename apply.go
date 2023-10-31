package autoupdate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func Apply(src, dest string, opts Options) error {
	return apply(src, dest, opts)
}

func apply(src, dest string, opts Options) error {
	fis, err := os.ReadDir(src)
	if err != nil {
		return errors.New("读目录 '" + src + "' 失败: " + err.Error())
	}

	for _, fi := range fis {
		if fi.IsDir() {
			copyed := opts
			if copyed.BackupDir != "" {
				copyed.BackupDir = filepath.Join(copyed.BackupDir, fi.Name())
			}
			err := apply(filepath.Join(src, fi.Name()), filepath.Join(dest, fi.Name()), copyed)
			if err != nil {
				return err
			}
		} else {
			err := applyFile(filepath.Join(src, fi.Name()), dest, opts)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func applyFile(srcFile, destDir string, opts Options) error {
	filename := filepath.Base(srcFile)
	destFile := filepath.Join(destDir, filename)

	st, err := os.Lstat(destFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("尝试更新文件 '" + destFile + "' 失败: " + err.Error())
		}
		st = nil
	}
	if st != nil {
		if st.Mode()&os.ModeSymlink == 0 {
			err := archiveFile(destFile, opts.BackupDir)
			if err != nil {
				return errors.New("尝试档案化文件 '" + destFile + "' 失败: " + err.Error())
			}
		}

		if err := os.Remove(destFile + ".old"); err != nil {
			if !os.IsNotExist(err) {
				return errors.New("尝试删除文件 '" + destFile + ".old' 失败: " + err.Error())
			}
		}
		if err := os.Rename(destFile, destFile+".old"); err != nil {
			return errors.New("尝试改名文件 '" + destFile + "' 失败: " + err.Error())
		}
	} else {
		if err = os.MkdirAll(destDir, 0775); err != nil {
			return errors.New("尝试新建目录 '" + destDir + "' 失败: " + err.Error())
		}
	}

	var lastErr error
	for i := 0; ; i++ {
		if i >= 10 {
			return errors.New("尝试建立 '" + srcFile + "' -> '" + destFile + "' 失败: " + lastErr.Error())
		}

		lastErr = os.Symlink(srcFile, destFile)
		if lastErr == nil {
			break
		}
	}
	return nil
}

func archiveFile(srcFile, destDir string) error {
	if err := os.MkdirAll(destDir, 0775); err != nil {
		return errors.New("尝试新建档案目录 '" + destDir + "' 失败: " + err.Error())
	}

	destFile := filepath.Join(destDir, filepath.Base(srcFile))
	for i := 0; ; i++ {
		if _, err := os.Stat(destFile); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			break
		} else {
			destFile = destFile + ".bak" + strconv.Itoa(i)
		}
	}
	return copyFile(srcFile, destFile)
}

func copyFile(src, dst string) (err error) {
	var in, out *os.File

	if in, err = os.Open(src); err != nil {
		return err
	}
	defer in.Close()

	if out, err = os.Create(dst); err != nil {
		return err
	}
	defer func() {
		if out != nil {
			cerr := out.Close()
			if err == nil {
				err = cerr
			}
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Close()
	out = nil
	return err
}
