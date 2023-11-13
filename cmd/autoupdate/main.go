package main

import (
	"flag"
	"net/http"
	"path/filepath"

	"github.com/mei-rune/autoupdate"
	"github.com/runner-mei/command"
)

type Base struct {
	dir        string
	signMethod string
	certFile   string
	privateKey string
	publicKey  string
}

func (b *Base) init() {
	if b.certFile == "" {
		b.certFile = filepath.Join(b.dir, "cert.pem")
	}
	if b.privateKey == "" {
		b.privateKey = filepath.Join(b.dir, "key.pem")
	}
	if b.publicKey == "" {
		b.publicKey = filepath.Join(b.dir, "pub.pem")
	}
}

func (b *Base) Flags(fs *flag.FlagSet) *flag.FlagSet {
	fs.StringVar(&b.dir, "dir", "", "仓库路径")
	fs.StringVar(&b.signMethod, "sign_method", "", "Hash 算法")
	fs.StringVar(&b.certFile, "certFile", "", "")
	fs.StringVar(&b.privateKey, "privateKey", "", "")
	fs.StringVar(&b.publicKey, "publicKey", "", "")
	return fs
}

type Service struct {
	Base

	https  bool
	listen string
	prefix string
}

func (s *Service) Flags(fs *flag.FlagSet) *flag.FlagSet {
	fs = s.Base.Flags(fs)

	fs.BoolVar(&s.https, "https", true, "启用 https")
	fs.StringVar(&s.listen, "listen", ":37152", "监听地址")
	fs.StringVar(&s.prefix, "prefix", "", "url 前缀")
	return fs
}

func (s *Service) Run(args []string) error {
	if len(args) != 0 {
		return &command.Error{
			Code:    1,
			Message: "参数错误",
			Help:    true,
		}
	}

	hs, err := autoupdate.NewHTTPServer(s.dir, s.signMethod, s.privateKey)
	if err != nil {
		return err
	}

	if s.https {
		err = http.ListenAndServeTLS(s.listen, s.certFile, s.privateKey, hs)
	} else {
		err = http.ListenAndServe(s.listen, hs)
	}
	return err
}

func main() {
	command.On("service", "作为一个服务运行", &Service{}, nil)
	command.DefaultCommandName = "service"
	command.Parse()
	command.Run()
}
