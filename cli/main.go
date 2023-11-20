package cli

import (
	"errors"
	"flag"
	"net/http"
	"path/filepath"

	"github.com/mei-rune/autoupdate"
	"github.com/runner-mei/command"
)

var On = command.On
var Parse = command.Parse
var Run = command.Run

func SetDefaultParsePostHook(hook func()) {
	command.SetDefaultParsePostHook(hook)
}

var (
	defaultHttps  bool   = true
	defaultListen string = ":37152"
	defaultPrefix string
	defaultDir    string
	// defaultSeparate bool
)

func SetDefaultDir(dir string) {
	defaultDir = dir
}

// func SetDefaultSeparate(b bool) {
// 	defaultSeparate = b
// }

func SetDefaultHttps(b bool) {
	defaultHttps = b
}

func SetDefaultListenAddress(b string) {
	defaultListen = b
}

func SetDefaultHttpPrefix(b string) {
	defaultPrefix = b
}

type Base struct {
	dir        string
	signMethod string
	certFile   string
	privateKey string
	publicKey  string
	// separate   bool
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
	fs.StringVar(&b.dir, "dir", defaultDir, "仓库路径")
	fs.StringVar(&b.signMethod, "sign_method", "", "Hash 算法")
	fs.StringVar(&b.certFile, "certFile", "", "")
	fs.StringVar(&b.privateKey, "privateKey", "", "")
	fs.StringVar(&b.publicKey, "publicKey", "", "")
	// fs.BoolVar(&b.separate, "separate", defaultSeparate, "")
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

	fs.BoolVar(&s.https, "https", defaultHttps, "启用 https")
	fs.StringVar(&s.listen, "listen", defaultListen, "监听地址")
	fs.StringVar(&s.prefix, "prefix", defaultPrefix, "url 前缀")
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
	s.Base.init()

	var hs http.Handler
	//if s.separate {
	rm, err := autoupdate.ReadRepoManager(s.dir, s.signMethod, s.privateKey)
	if err != nil {
		return err
	}
	hs = http.StripPrefix(s.prefix, rm)
	// } else {
	// 	h, err := autoupdate.NewHTTPServer("default", s.dir, s.signMethod, s.privateKey)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	hs = http.StripPrefix(s.prefix, h)
	// }

	// var err error
	if s.https {
		err = http.ListenAndServeTLS(s.listen, s.certFile, s.privateKey, hs)
	} else {
		err = http.ListenAndServe(s.listen, hs)
	}

	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func init() {
	command.On("service", "作为一个服务运行", &Service{}, nil)
	command.DefaultCommandName = "service"
}
