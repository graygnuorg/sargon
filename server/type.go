package server

import (
	"os"
	"errors"
	"encoding/json"
	"io/ioutil"
	"log"
	"sargon/access"
)

type Sargon struct {
	PidFile string
	LdapConf string
	LdapUser string
	LdapPass string
	LdapTLS bool
	AnonymousUser string
	ACL access.ACL
}

func (srg *Sargon) ReadConfig(f string) {
	raw, err := ioutil.ReadFile(f)
	if err == nil {
		if err = json.Unmarshal(raw, srg); err != nil {
			log.Fatalln(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatalln(err)
	}
}

