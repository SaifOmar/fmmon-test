package main

import "github.com/saif/spoofer/engine"

type SpoofService struct {
	Devices *engine.DeviceMap
}

func (g *SpoofService) GetDevices() engine.DeviceMap {
	e := &engine.Engine{}
	go engine.Start(e)
	return e.Devices
}
