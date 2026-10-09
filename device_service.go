package main

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"

	"github.com/saif/spoofer/engine"
)

type DeviceService struct {
	Engine *engine.Engine

	mu         sync.RWMutex
	startupErr string
}

// SetStartupError records a fatal problem (missing capability, engine panic) so
// the UI can render it instead of the app vanishing.
func (s *DeviceService) SetStartupError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startupErr = msg
}

// StartupError returns the recorded startup problem, or "" when healthy.
func (s *DeviceService) StartupError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.startupErr
}

type StatusView struct {
	Error string `json:"error"`
}

// Status returns any fatal startup problem for the UI banner.
func (s *DeviceService) Status() StatusView {
	return StatusView{Error: s.StartupError()}
}

type DeviceView struct {
	Name        string   `json:"name"`
	IP          string   `json:"ip"`
	MAC         string   `json:"mac"`
	Vendor      string   `json:"vendor"`
	UpRate      string   `json:"upRate"`
	DownRate    string   `json:"downRate"`
	UpLimit     string   `json:"upLimit"`
	DownLimit   string   `json:"downLimit"`
	UpLimitKB   float64  `json:"upLimitKB"`
	DownLimitKB float64  `json:"downLimitKB"`
	State       []string `json:"state"`
}

func (s *DeviceService) GetDevices() []DeviceView {
	found := s.Engine.DevicesSnapshot()

	out := make([]DeviceView, 0, len(found))
	for _, d := range found {
		state := []string{"reachable"}
		if d.Blocked {
			state = []string{"blocked"}
		} else if d.UpClass != "" || d.DownClass != "" {
			state = []string{"limited"}
		}
		out = append(out, DeviceView{
			Name:        d.Name,
			IP:          d.IP.String(),
			MAC:         hardwareAddrString(d.MAC),
			Vendor:      d.Name,
			UpRate:      formatRate(d.UpRate),
			DownRate:    formatRate(d.DownRate),
			UpLimit:     formatLimit(d.UpRateLimit),
			DownLimit:   formatLimit(d.DownRateLimit),
			UpLimitKB:   kbitToKB(d.UpRateLimit),
			DownLimitKB: kbitToKB(d.DownRateLimit),
			State:       state,
		})
	}

	// Go randomizes map iteration order, so sort to keep the table from
	// reshuffling on every poll. Numeric IP, not string, so .100 precedes .24.
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].IP).To4(), net.ParseIP(out[j].IP).To4()
		if a == nil || b == nil {
			return out[i].IP < out[j].IP
		}
		if c := bytes.Compare(a, b); c != 0 {
			return c < 0
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func hardwareAddrString(b []byte) string {
	if b == nil {
		return ""
	}
	return net.HardwareAddr(b).String()
}

// findDevice locates a live device by its dotted-quad IP.
func (s *DeviceService) findDevice(ip string) (*engine.Device, error) {
	d, ok := s.Engine.DeviceByIP(ip)
	if !ok {
		return nil, fmt.Errorf("no device with ip %s", ip)
	}
	return d, nil
}

// SetBlocked drops or restores forwarding for a device. Toggling in one method
// keeps the UI checkbox from drifting out of sync with the engine's own flag.
func (s *DeviceService) SetBlocked(ip string, blocked bool) error {
	d, err := s.findDevice(ip)
	if err != nil {
		return err
	}
	if blocked {
		return engine.BlockDevice(d)
	}
	return engine.UnblockDevice(d)
}

// SetRateLimit applies per-direction caps in kb/s. A value of 0 clears that
// direction's limit. Each direction keeps its own htb class, reused on later
// changes so the engine switches the existing rule instead of adding a second.
func (s *DeviceService) SetRateLimit(ip string, upKB, downKB float64) error {
	d, err := s.findDevice(ip)
	if err != nil {
		return err
	}
	host := s.Engine.Host
	if host.Interface == "" {
		return fmt.Errorf("host interface unknown; engine may not be ready")
	}

	if upKB <= 0 {
		if d.UpClass != "" {
			s.Engine.FreeClassNumber(engine.ParseDevClass(d.UpClass))
		}
		if err := engine.ClearUpRateLimit(d, host); err != nil {
			return err
		}
	} else {
		class := d.UpClass
		if class == "" {
			var err error
			if class, err = s.newDevClass(); err != nil {
				return err
			}
		}
		if err := engine.UpRateLimitDevice(d, host, kbToKbit(upKB), class); err != nil {
			return err
		}
	}

	if downKB <= 0 {
		if d.DownClass != "" {
			s.Engine.FreeClassNumber(engine.ParseDevClass(d.DownClass))
		}
		if err := engine.ClearDownRateLimit(d, host); err != nil {
			return err
		}
	} else {
		class := d.DownClass
		if class == "" {
			var err error
			if class, err = s.newDevClass(); err != nil {
				return err
			}
		}
		if err := engine.DownRateLimitDevice(d, host, kbToKbit(downKB), class); err != nil {
			return err
		}
	}
	return nil
}

// newDevClass allocates a fresh htb class, or reports the pool is full.
func (s *DeviceService) newDevClass() (string, error) {
	n := s.Engine.TcGetClassNumber()
	if n == 0 {
		return "", fmt.Errorf("all %d tc classes are in use; clear a limit first", 999)
	}
	return fmt.Sprintf("1:%d", n), nil
}

// kbToKbit converts the UI's decimal kilobytes per second into the kilobits
// per second the engine stores and tc is given.
func kbToKbit(kbPerSecond float64) float64 {
	return kbPerSecond * 8
}

// kbitToKB inverts kbToKbit so the UI can prefill its boxes.
func kbitToKB(kbitPerSecond float64) float64 {
	return kbitPerSecond / 8
}

// formatRate renders a byte-per-second counter in the largest unit that keeps
// the number readable, so a busy link reads "12 mb/s" instead of "12000 kb/s".
// Units are decimal (1 kb = 1000 bytes), matching the /1000 the engine implies.
func formatRate(bytesPerSecond float64) string {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}

	units := [...]string{"kb/s", "mb/s", "gb/s"}
	unit, scale := 0, 1000.0
	value := bytesPerSecond / scale

	// Climb until the number as it will actually be printed stays under 1000.
	// Comparing the raw value would let 999999999 B/s print as "1000 mb/s".
	for unit < len(units)-1 && displayedValue(value) >= 1000 {
		unit++
		scale *= 1000
		value = bytesPerSecond / scale
	}

	return formatScaled(value, units[unit])
}

// displayedValue rounds the way formatScaled prints, so unit promotion agrees
// with the digits on screen instead of rounding past the boundary later.
func displayedValue(value float64) float64 {
	if value < 10 {
		return math.Round(value*10) / 10
	}
	return math.Round(value)
}

func formatScaled(value float64, unit string) string {
	if value < 10 {
		return fmt.Sprintf("%.1f %s", value, unit)
	}
	return fmt.Sprintf("%.0f %s", value, unit)
}

// formatLimit renders an applied cap, which the engine stores in kbit. It goes
// back to kb/s so it reads the same as the live rate next to it.
func formatLimit(kbitPerSecond float64) string {
	if kbitPerSecond <= 0 {
		return ""
	}
	return formatRate(kbitToKB(kbitPerSecond))
}
