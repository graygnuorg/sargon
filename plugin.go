package main

import (
	"bytes"
	"strings"
	"regexp"
	"path/filepath"
	"net/url"
	"encoding/json"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/engine-api/types/mount"
	"log"
)	

func realpath(s string) (string, error) {
        path, err := filepath.EvalSymlinks(s)
        if err != nil {
	        return s, err;
	}
        return filepath.Abs(path);
}

func mountAllowed(dir string) bool {
        path, err := realpath(dir)
	if err != nil {
	        log.Println(err.Error());
		return false
        }			
	for _, x := range config.Mount {
		if strings.HasPrefix(path, x) {
			return true
		}
        }
	return false
}

type sargon struct {
}

func newPlugin() (*sargon, error) {
	return &sargon{}, nil
}

type configWrapper struct {
	*container.Config
	HostConfig       *container.HostConfig
}

var createRe = regexp.MustCompile(`/v.*/containers/create`)

func (p *sargon) AuthZReq(req authorization.Request) authorization.Response {

	uri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	// Remove query parameters
	uri = (strings.SplitN(uri,"?",2))[0];

	log.Println("checking "+req.RequestMethod+" request to '"+uri+"' from user : "+req.User)

	if req.RequestMethod == "POST" && createRe.MatchString(uri) {
		if req.RequestBody != nil {
			body := &configWrapper{}
			if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
				return authorization.Response{Err: err.Error()}
			}

			// Deny creation of privileged containers
			if !config.AllowPriv && body.HostConfig.Privileged {
				return authorization.Response{Msg: "privileged containers are not allowed"}
			}

			// Check binds (the old API)
			for _, b := range body.HostConfig.Binds {
			        a := strings.SplitN(b, ":", 2)
				if !mountAllowed(a[0]) {
				        return authorization.Response{Msg: "mounting "+a[0]+" is not allowed"}
				}
			}

			// Check mounts (new API)
			for _, m := range body.HostConfig.Mounts {
				if m.Type == mount.TypeBind && !mountAllowed(m.Source) {
				        return authorization.Response{Msg: "mounting "+m.Source+" is not allowed"}
				}

			}
		}
	}

	return authorization.Response{Allow: true}
}

func (p *sargon) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

