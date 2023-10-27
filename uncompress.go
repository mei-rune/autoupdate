package autoupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
)

func Uncompress(filename, targetDir string) error {
	if strings.HasSuffix(filename, ".zip") {
		return uncompressZip(filename, targetDir)
	} else if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		return uncompressTargz(filename, targetDir)
		// } else if strings.HasSuffix(filename, ".tar.xz") {
		// 	return uncompressTarxz(filename, targetDir)
	}
	return errors.New("文件格式不支持 - '" + filepath.Base(filename) + "'")
}

func uncompressZip(filename string, targetDir string) error {
	files, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer files.Close()

	for _, file := range files.File {
		err = func() error {
			readCloser, err := file.Open()
			if err != nil {
				return err
			}
			defer readCloser.Close()

			return extractZipArchiveFile(file, targetDir, readCloser)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractZipArchiveFile(file *zip.File, dest string, input io.Reader) error {
	filePath, err := securejoin.SecureJoin(dest, file.Name)
	fileInfo := file.FileInfo()

	if fileInfo.IsDir() {
		err = os.MkdirAll(filePath, fileInfo.Mode())
		if err != nil {
			return err
		}
	} else {
		err = os.MkdirAll(filepath.Dir(filePath), 0755)
		if err != nil {
			return err
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			linkName, err := ioutil.ReadAll(input)
			if err != nil {
				return err
			}
			return os.Symlink(string(linkName), filePath)
		}

		fileCopy, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileInfo.Mode())
		if err != nil {
			return err
		}
		defer fileCopy.Close()

		_, err = io.Copy(fileCopy, input)
		if err != nil {
			return err
		}
	}

	return nil
}

func uncompressTar(filename string, targetDir string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fd.Close()

	tarReader := tar.NewReader(fd)
	return extractTarArchive(tarReader, targetDir)
}

func uncompressTargz(filename string, targetDir string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fd.Close()

	gReader, err := gzip.NewReader(fd)
	if err != nil {
		return err
	}
	defer gReader.Close()

	tarReader := tar.NewReader(gReader)
	return extractTarArchive(tarReader, targetDir)
}

func extractTarArchive(tarReader *tar.Reader, dest string) error {
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if hdr.Name == "." {
			continue
		}

		err = extractTarArchiveFile(hdr, dest, tarReader)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarArchiveFile(header *tar.Header, dest string, input io.Reader) error {
	filePath, err := securejoin.SecureJoin(dest, header.Name)
	if err != nil {
		return err
	}
	fileInfo := header.FileInfo()
	if fileInfo.IsDir() {
		return os.MkdirAll(filePath, fileInfo.Mode())
	}

	err = os.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return err
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return os.Symlink(header.Linkname, filePath)
	}

	fileCopy, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileInfo.Mode())
	if err != nil {
		return err
	}
	defer fileCopy.Close()

	_, err = io.Copy(fileCopy, input)
	return err
}

// func uncompressTarxz(f *zip.File, targetDir string) error {
//   fd, err := os.Open(src)
//   if err != nil {
//     return err
//   }
//   defer fd.Close()

//   xzReader, err := xz.NewReader(fd)
//   if err != nil {
//     return err
//   }
//   defer xzReader.Close()

//   tarReader := tar.NewReader(xzReader)
//   return extractTarArchive(tarReader, dest)
// }
//
