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
	"fmt"
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

func capAllowed(cap string) bool {
	if len(config.AllowCapAdd) == 0 {
		return true;
	}
	return config.CapAddMap[normalizeCap(cap)]
}

type sargon struct {
}

func newPlugin() (*sargon, error) {
	return &sargon{}, nil
}

type createRequest struct {
	*container.Config
	HostConfig       *container.HostConfig
}

func allowCreate(body *createRequest, config *Config) (bool, string) {
	// Deny creation of privileged containers
	if !config.AllowPriv && body.HostConfig.Privileged {
		return false, "privileged containers are not allowed"
	}

	// Check binds (the old API)
	for _, b := range body.HostConfig.Binds {
		a := strings.SplitN(b, ":", 2)
		if !mountAllowed(a[0]) {
			return false, "mounting " + a[0] + " is not allowed"
		}
	}

	// Check mounts (new API)
	for _, m := range body.HostConfig.Mounts {
		if m.Type == mount.TypeBind && !mountAllowed(m.Source) {
			return false, "mounting " + m.Source + " is not allowed"
		}
	}

	// Check capabilities
	for _, cap := range body.HostConfig.CapAdd {
		if !capAllowed(cap) {
			return false, "capability " + cap + " is not allowed"
		}
	}

	// Check requested memory sizes
	if config.MaxMemory > 0 &&
		(body.HostConfig.Memory == 0 ||
		body.HostConfig.Memory > config.MaxMemory) {
		return false, "memory limit must be lower than or equal to " + fmt.Sprintf("%v",config.MaxMemory)
	}
	if config.MaxKernelMemory > 0 &&
		(body.HostConfig.KernelMemory == 0 ||
		 body.HostConfig.KernelMemory >
			     config.MaxKernelMemory) {
		return false, "kernel memory limit must be lower than or equal to " + fmt.Sprintf("%v",config.MaxKernelMemory)
        }
	return true, "Ok"
}

var createRe = regexp.MustCompile(`/v.*/(containers|volumes)/create`)

func (p *sargon) AuthZReq(req authorization.Request) authorization.Response {

	uri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	// Remove query parameters
	uri = (strings.SplitN(uri,"?",2))[0];

	log.Println("checking "+req.RequestMethod+" request to '"+uri+"' from user: "+req.User)

	if req.RequestMethod == "POST" {
		if res := createRe.FindStringSubmatch(uri); res != nil && req.RequestBody != nil {
			body := &createRequest{}
			if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
				return authorization.Response{Err: err.Error()}
			}

			if res[1] == `containers` {
				if res, msg := allowCreate(body, &config);
				   res == false {
					return authorization.Response{Msg: msg}
	 		        }
			}
		}
	}

	return authorization.Response{Allow: true}
}

func (p *sargon) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

