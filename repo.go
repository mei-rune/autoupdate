package autoupdate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

func ReadRepoManager(rootDir, signMethod, defaultPrivateFile string) (*RepoManager, error) {
	fis, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return nil, err
	}

	rm := &RepoManager{
		defaultPrivateFile: defaultPrivateFile,
		rootDir:            rootDir,
		signMethod:         signMethod,
	}

	ctx := context.Background()
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		_, err := rm.readDir(ctx, fi.Name())
		if err != nil {
			log.Println("load dir '"+fi.Name()+"' fail,", err)
		} else {
			log.Println("load dir '" + fi.Name() + "' ok")
		}
	}
	return rm, nil
}

type Repo struct {
	Prefix  string
	Handler http.Handler
}

type RepoManager struct {
	defaultPrivateFile string
	rootDir            string
	signMethod         string
	list               atomic.Value
	mu                 sync.Mutex
}

func (rm *RepoManager) readDir(ctx context.Context, dir string) (Repo, error) {
	repo, err := readDir(rm.rootDir, dir, rm.signMethod, rm.defaultPrivateFile)
	if err != nil {
		return Repo{}, err
	}
	rm.Add(repo)
	return repo, nil
}

func (rm *RepoManager) Add(repo Repo) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := rm.ReadonlyList()
	for _, rp := range list {
		if strings.EqualFold(rp.Prefix, repo.Prefix) {
			panic(errors.New("repo '" + rp.Prefix + "' is already exists"))
		}
	}
	copyed := make([]Repo, len(list), len(list)+1)
	copy(copyed, list)
	copyed = append(copyed, repo)
	rm.list.Store(copyed)
}

func (rm *RepoManager) RemoveByPrefix(prefix string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list := rm.ReadonlyList()
	copyed := make([]Repo, 0, len(list))
	for _, repo := range list {
		if !strings.EqualFold(repo.Prefix, prefix) {
			continue
		}
		copyed = append(copyed, repo)
	}
	rm.list.Store(copyed)
}

func (rm *RepoManager) ReadonlyList() []Repo {
	o := rm.list.Load()
	if o == nil {
		return nil
	}
	list, ok := o.([]Repo)
	if !ok {
		return nil
	}
	return list
}

func (rm *RepoManager) CreateRepo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(defaultMaxMemory)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	names := r.MultipartForm.Value["name"]
	switch len(names) {
	case 0:
		http.Error(w, "请指标仓库名", http.StatusBadRequest)
		return
	case 1:
	default:
		http.Error(w, "你指定了多个仓库名", http.StatusBadRequest)
		return
	}
	reponame := strings.Trim(names[0], "/")
	if reponame == "" {
		http.Error(w, "仓库路径不正确", http.StatusBadRequest)
		return
	}
	if strings.Contains(reponame, "/") {
		http.Error(w, "仓库路径不正确", http.StatusBadRequest)
		return
	}

	var file multipart.File
	for _, files := range r.MultipartForm.File {
		if len(files) == 0 {
			continue
		}

		filename := filepath.Base(files[0].Filename)
		if filename != "key.pem" {
			continue
		}

		file, err = files[0].Open()
		if err != nil {
			http.Error(w, "读附件 '"+files[0].Filename+"' 失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
	}

	dirpath := filepath.Join(rm.rootDir, reponame)
	if err := os.MkdirAll(dirpath, 0666); err != nil {
		if !os.IsExist(err) {
			http.Error(w, "创建目录失败:"+err.Error(), http.StatusBadRequest)
			return
		}
	}

	pemFilename := filepath.Join(dirpath, "key.pem")
	if file != nil {
		if err = copyReaderToFile(file, pemFilename); err != nil {
			http.Error(w, "保存 key.pem 文件失败:"+err.Error(), http.StatusBadRequest)
			return
		}
	} else if values := r.MultipartForm.Value["use_default_key"]; len(values) > 0 && values[len(values)-1] == "true" {
		//
	} else {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			http.Error(w, "生成 private key 失败:"+err.Error(), http.StatusBadRequest)
			return
		}
		keyOut, err := os.Create(pemFilename)
		if err != nil {
			http.Error(w, "创建 key.pem 失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}
		pem.Encode(keyOut, block)
		keyOut.Close()
	}

	repo, err := readDir(rm.rootDir, reponame, rm.signMethod, rm.defaultPrivateFile)
	if err != nil {
		http.Error(w, "加载 key.pem 失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	rm.Add(repo)

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "{\"code\": 200}")
}

func (rm *RepoManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rm.ServeHTTPWithContext(r.Context(), w, r, r.URL.Path)
}

func (rm *RepoManager) ServeHTTPWithContext(ctx context.Context, w http.ResponseWriter, r *http.Request, pa string) {
	list := rm.ReadonlyList()

	if pa == "" || pa == "/" {
		if r.Method == http.MethodPost {
			rm.CreateRepo(ctx, w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{")
		for idx, repo := range list {
			if idx > 0 {
				io.WriteString(w, ",")
			}
			fmt.Fprintf(w, "%q", repo.Prefix)
		}
		io.WriteString(w, "}")
		return
	}

	for _, repo := range list {
		if strings.HasPrefix(pa, repo.Prefix) || pa == repo.Prefix || (pa+"/") == repo.Prefix {
			repo.Handler.ServeHTTP(w, r)
			return
		}
	}

	// if strings.HasPrefix("/@/") {
	// }

	pa = strings.Trim(pa, "/")
	index := strings.Index(pa, "/")
	if index > 0 {
		dir := pa[:index]

		repo, err := rm.readDir(ctx, dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		repo.Handler.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

func readDir(rootdir, dirname, signMethod, defaultPrivateFile string) (Repo, error) {
	dirpath := filepath.Join(rootdir, dirname)
	st, err := os.Stat(dirpath)
	if err != nil {
		return Repo{}, err
	}
	if !st.IsDir() {
		return Repo{}, errors.New("'" + dirpath + "' isnot directory")
	}
	repo := Repo{
		Prefix: "/" + strings.Trim(dirname, "/") + "/",
		// Handler: hs,
		// CertFile:
		// PrivateKey:
		// PublicKey:
	}
	// repo.CertFile = filepath.Join(dirpath, "cert.pem")
	// repo.PrivateKey = filepath.Join(dirpath, "key.pem")
	// repo.PublicKey = filepath.Join(dirpath, "pub.pem")

	privateFile := filepath.Join(dirpath, "key.pem")
	st, err = os.Stat(privateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return Repo{}, err
		}
		privateFile = defaultPrivateFile
	} else {
		if !st.IsDir() {
			return Repo{}, errors.New("'" + dirpath + "' isnot private file")
		}
	}

	hs, err := NewHTTPServer(dirname, rootdir, signMethod, privateFile)
	if err != nil {
		return Repo{}, err
	}
	repo.Handler = hs
	return repo, nil
}
