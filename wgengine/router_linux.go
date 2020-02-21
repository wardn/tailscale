// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/atomicfile"
	"tailscale.com/types/logger"
)

type linuxRouter struct {
	logf    func(fmt string, args ...interface{})
	tunname string
	local   wgcfg.CIDR
	routes  map[wgcfg.CIDR]struct{}
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tunDev tun.Device) (Router, error) {
	tunname, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	return &linuxRouter{
		logf:    logf,
		tunname: tunname,
	}, nil
}

func cmd(args ...string) *exec.Cmd {
	if len(args) == 0 {
		log.Fatalf("exec.Cmd(%#v) invalid; need argv[0]\n", args)
	}
	return exec.Command(args[0], args[1:]...)
}

func (r *linuxRouter) Up() error {
	out, err := cmd("ip", "link", "set", r.tunname, "up").CombinedOutput()
	if err != nil {
		// TODO: this should return an error; why is it calling log.Fatalf?
		// Audit callers to make sure they're handling errors.
		log.Fatalf("running ip link failed: %v\n%s", err, out)
	}

	// TODO(apenwarr): This never cleans up after itself!
	out, err = cmd("iptables",
		"-A", "FORWARD",
		"-i", r.tunname,
		"-j", "ACCEPT").CombinedOutput()
	if err != nil {
		r.logf("iptables forward failed: %v\n%s", err, out)
	}
	// TODO(apenwarr): hardcoded eth0 interface is obviously not right.
	out, err = cmd("iptables",
		"-t", "nat",
		"-A", "POSTROUTING",
		"-o", "eth0",
		"-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		r.logf("iptables nat failed: %v\n%s", err, out)
	}
	return nil
}

func (r *linuxRouter) SetRoutes(rs RouteSettings) error {
	var errq error

	if rs.LocalAddr != r.local {
		if r.local != (wgcfg.CIDR{}) {
			addrdel := []string{"ip", "addr",
				"del", r.local.String(),
				"dev", r.tunname}
			out, err := cmd(addrdel...).CombinedOutput()
			if err != nil {
				r.logf("addr del failed: %v: %v\n%s", addrdel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
		addradd := []string{"ip", "addr",
			"add", rs.LocalAddr.String(),
			"dev", r.tunname}
		out, err := cmd(addradd...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v: %v\n%s", addradd, err, out)
			if errq == nil {
				errq = err
			}
		}
	}

	newRoutes := make(map[wgcfg.CIDR]struct{})
	for _, peer := range rs.Cfg.Peers {
		for _, route := range peer.AllowedIPs {
			newRoutes[route] = struct{}{}
		}
	}
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			addrdel := []string{"ip", "route",
				"del", nstr,
				"via", r.local.IP.String(),
				"dev", r.tunname}
			out, err := cmd(addrdel...).CombinedOutput()
			if err != nil {
				r.logf("addr del failed: %v: %v\n%s", addrdel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}
	for route := range newRoutes {
		if _, exists := r.routes[route]; !exists {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			addradd := []string{"ip", "route",
				"add", nstr,
				"via", rs.LocalAddr.IP.String(),
				"dev", r.tunname}
			out, err := cmd(addradd...).CombinedOutput()
			if err != nil {
				r.logf("addr add failed: %v: %v\n%s", addradd, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}

	r.local = rs.LocalAddr
	r.routes = newRoutes

	// TODO: this:
	if false {
		if err := replaceResolvConf(rs.DNS, rs.DNSDomains, r.logf); err != nil {
			errq = fmt.Errorf("replacing resolv.conf failed: %v", err)
		}
		restartSystemd(r.logf)
	}
	return errq
}

func (r *linuxRouter) Close() error {
	var ret error
	if err := restoreResolvConf(r.logf); err != nil {
		r.logf("failed to restore system resolv.conf: %v", err)
		if ret == nil {
			ret = err
		}
	}
	restartSystemd(logf)
	// TODO(apenwarr): clean up iptables etc.
	return ret
}

func restartSystemd(logf logger.Logf) {
	out, _ := exec.Command("service", "systemd-resolved", "restart").CombinedOutput()
	if len(out) > 0 {
		logf("service systemd-resolved restart: %s", out)
	}
}
