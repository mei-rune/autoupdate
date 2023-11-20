package autoupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

func (rm *RepoManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rm.ServeHTTPWithContext(r.Context(), w, r, r.URL.Path)
}

func (rm *RepoManager) ServeHTTPWithContext(ctx context.Context, w http.ResponseWriter, r *http.Request, pa string) {
	list := rm.ReadonlyList()

	if pa == "" || pa == "/" {
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
