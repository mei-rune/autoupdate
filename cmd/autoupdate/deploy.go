package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"net/http"

	"github.com/mei-rune/autoupdate"
	"github.com/runner-mei/command"
)

func init() {
	command.On("deploy", "上传一个补丁", &Deploy{}, nil)
}

type Deploy struct {
	// Base

	u       string
	repo    string
	version string
	arch    string

	basedir string
}

func (s *Deploy) Flags(fs *flag.FlagSet) *flag.FlagSet {
	// fs = s.Base.Flags(fs)
	fs.StringVar(&s.u, "url", "http://127.0.0.1:37152", "补丁服务器的地址")
	fs.StringVar(&s.repo, "repo", "", "补丁服务器的仓库名称")
	fs.StringVar(&s.version, "version", "", "补丁服务器的地址")
	fs.StringVar(&s.arch, "arch", "", "操作系统，可取值: windows_amd64, linux_amd64")
	fs.StringVar(&s.basedir, "basedir", "", "补丁文件的根目录")
	return fs
}

func (s *Deploy) Run(args []string) error {
	var filename string
	var err error

	switch s.arch {
	case "windows_amd64":
		filename = s.arch + ".zip"
		err = autoupdate.Compress(filename, s.basedir, args)
	case "linux_amd64":
		filename = s.arch + ".tar.gz"
		err = autoupdate.Compress(filename, s.basedir, args)
	default:
		return errors.New("参数 '" + s.arch + "' 不正确")
	}
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return autoupdate.DeployWithOnlyPackageFile(client, nil, s.u, filename)
}
