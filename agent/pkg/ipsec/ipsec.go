package ipsec

import (
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type IPSec interface {
}

type SysIPSec struct {
	NsName string
}

func (i *SysIPSec) getNetlinkHandle() (*netlink.Handle, error) {
	if i.NsName != "" {
		// Get netns by name
		nsHandle, err := netns.GetFromName(i.NsName)
		if err != nil {
			return nil, err
		}

		// Switch current handle to netns handle
		err = netns.Set(nsHandle)
		if err != nil {
			return nil, err
		}

		handle, err := netlink.NewHandleAt(nsHandle, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}

		return handle, nil
	}

	handle, err := netlink.NewHandle(netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func (i *SysIPSec) SAList() ([]netlink.XfrmState, error) {
	handle, err := i.getNetlinkHandle()
	if err != nil {
		return nil, err
	}

	xfrmStates, err := handle.XfrmStateList(netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	return xfrmStates, nil
}
