package main

import (
	"fmt"
	"io/ioutil"

	"github.com/mei-rune/autoupdate"
)

func main() {
	fs, err := autoupdate.ReadEmbedDir()
	if err != nil {
		fmt.Println(err)
		return
	}

	out, err := fs.Open("file.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer out.Close()

	bs, err := ioutil.ReadAll(out)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bs))
}
