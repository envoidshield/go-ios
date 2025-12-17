package ncm

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/gousb"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

const VID_APPLE = 0x5ac
const PID_RANGE_LOW = 0x1290
const PID_RANGE_MAX = 0x12af
const PID_APPLE_T2_COPROCESSOR = 0x8600
const PID_APPLE_SILICON_RESTORE_LOW = 0x1901
const PID_APPLE_SILICON_RESTORE_MAX = 0x1905

var allocatedDevices = sync.Map{}
var failedDevices = sync.Map{} // tracks devices that failed with cooldown
var serialToInterface = map[string]string{}
var deviceLock = sync.Mutex{}
var deviceCounter = 0

const deviceCooldownDuration = 5 * time.Second

func Start(c chan os.Signal) error {
	ctx := gousb.NewContext()
	defer ctx.Close()
	for {
		select {
		case <-time.After(500 * time.Millisecond):
			checkDevices(ctx)
			printStatus()
		case <-c:
			slog.Info("shut down complete")
			return nil
		}
	}
}

func printStatus() {
	var connectedDevices []string
	allocatedDevices.Range(func(key, value interface{}) bool {
		connectedDevices = append(connectedDevices, key.(string))
		return true
	})
	deviceCount.Set(float64(len(connectedDevices)))
	slices.Sort[[]string](connectedDevices)
	slog.Debug("connected devices", "devices", connectedDevices)
}

func checkDevices(ctx *gousb.Context) {
	devices, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		if desc.Vendor != VID_APPLE {
			return false
		}
		if desc.Product == PID_APPLE_T2_COPROCESSOR {
			return false
		}
		if desc.Product < PID_RANGE_LOW || desc.Product > PID_RANGE_MAX {
			return false
		}
		return true
	})
	if err != nil {
		slog.Error("failed opening devices", "err", err)
	}
	slog.Debug("device list", "length", len(devices))
	for _, d := range devices {
		// Check serial BEFORE spawning goroutine to avoid unnecessary goroutines
		serial, err := d.SerialNumber()
		if err != nil {
			d.Close()
			continue
		}
		serial = strings.Trim(serial, "\x00")
		
		// Skip if already being handled successfully
		if _, exists := allocatedDevices.Load(serial); exists {
			d.Close()
			continue
		}
		
		// Skip if device recently failed (cooldown)
		if failTime, exists := failedDevices.Load(serial); exists {
			if time.Since(failTime.(time.Time)) < deviceCooldownDuration {
				d.Close()
				continue
			}
			// Cooldown expired, remove from failed list and retry
			failedDevices.Delete(serial)
		}
		
		go func(d *gousb.Device, serial string) {
			err := handleDevice(d, serial)
			if err != nil {
				slog.Error("failed opening network adapter for device", "device", d.String(), "err", err)
				// Mark as failed with timestamp for cooldown
				failedDevices.Store(serial, time.Now())
			}
		}(d, serial)
	}
}

func updateInterface(serial string) {
	deviceLock.Lock()
	defer deviceLock.Unlock()
	_, ok := serialToInterface[serial]
	if ok {
		return
	}
	ifaceName := fmt.Sprintf("iphone%d", deviceCounter)
	slog.Info("assigning interface", "iface", ifaceName, "serial", serial)
	serialToInterface[serial] = ifaceName
	deviceCounter++
}

func interfaceName(serial string) string {
	deviceLock.Lock()
	defer deviceLock.Unlock()
	return serialToInterface[serial]
}

// tryNCMConfig tries to get the NCM config (config 5) directly
// If config 5 doesn't exist, falls back to trying all configs
func tryNCMConfig(device *gousb.Device, serial string) (*gousb.Config, error) {
	// NCM is always config 5 on iOS devices
	const ncmConfigNum = 5
	
	// Check if config 5 exists
	if _, hasConfig5 := device.Desc.Configs[ncmConfigNum]; hasConfig5 {
		slog.Debug("trying NCM config 5", "serial", serial)
		cfg, err := device.Config(ncmConfigNum)
		if err != nil {
			return nil, fmt.Errorf("failed to activate config 5: %w", err)
		}
		
		if hasNCMInterface(cfg) {
			slog.Info("found NCM interface on config 5", "serial", serial)
			return cfg, nil
		}
		
		cfg.Close()
		return nil, fmt.Errorf("config 5 exists but has no NCM interface")
	}
	
	// Config 5 doesn't exist - try other configs (fallback)
	slog.Debug("config 5 not available, trying other configs", "serial", serial)
	for configNum := range device.Desc.Configs {
		cfg, err := device.Config(configNum)
		if err != nil {
			slog.Debug("config attempt failed", "config_num", configNum, "serial", serial, "err", err)
			continue
		}
		
		if hasNCMInterface(cfg) {
			slog.Info("found NCM interface", "config_num", configNum, "serial", serial)
			return cfg, nil
		}
		cfg.Close()
	}
	
	return nil, fmt.Errorf("no NCM config found for device %s", serial)
}

// hasNCMInterface checks if a config has a valid NCM interface
func hasNCMInterface(cfg *gousb.Config) bool {
	for _, iface := range cfg.Desc.Interfaces {
		for _, alt := range iface.AltSettings {
			// NCM: class 10, subclass 0, with 2 endpoints (IN and OUT)
			if alt.Class == 10 && alt.SubClass == 0 && len(alt.Endpoints) == 2 {
				return true
			}
		}
	}
	return false
}

// handleDevice checks if the device has 5 usb configurations.
// USBMUXD should make sure they are already enabled. Without doing anything devices usually have 4.
// The 5th one should be the ncm driver. Then finds endpoints for the ncm network device, starts a virtual
// TAP network device and starts a read/write loop to send data from virtual network to USB and back
func handleDevice(device *gousb.Device, serial string) error {
	defer closeWithLog("device "+device.String(), device.Close)
	
	updateInterface(serial)
	_, loaded := allocatedDevices.LoadOrStore(serial, true)
	if loaded {
		slog.Info("device already handled", "serial", serial)
		return nil
	}
	// Note: We delete from allocatedDevices only when the device disconnects (ncmIOCopy returns)
	// This prevents infinite retry loops on failure
	slog.Info("got device", slog.String("serial", serial))

	activeConfig, err := device.ActiveConfigNum()
	if err != nil {
		return fmt.Errorf("handleDevice: failed to get active config for device %s with err %w", serial, err)
	}
	slog.Info("active config", slog.Int("active", activeConfig), "serial", serial)
	confLen := len(device.Desc.Configs)
	slog.Info("available configs", "configs", device.Desc.Configs, "len", confLen, "serial", serial)

	if confLen != 5 {
		slog.Info("enabling NCM config via control commands", "serial", serial, "currentConfigs", confLen)
		_, err = device.Control(0xc0, 69, 0, 0, make([]byte, 4))
		if err != nil {
			slog.Error("failed sending control1", slog.Any("error", err))
			return fmt.Errorf("handleDevice: failed sending control1 for device %s with err %w", serial, err)
		}

		_, err = device.Control(0xc0, 82, 0, 3, make([]byte, 1))
		if err != nil {
			slog.Error("failed sending control2", slog.Any("error", err))
			return fmt.Errorf("handleDevice: failed sending control2 for device %s with err %w", serial, err)
		}
		
		// Control commands cause device to reset and re-enumerate with new USB address
		// We MUST close this device handle and return - the next poll cycle will 
		// pick up the re-enumerated device with config 5 available
		slog.Info("NCM config enabled, device will re-enumerate", "serial", serial)
		allocatedDevices.Delete(serial) // Allow re-detection
		return nil // Return success - device will be re-detected with 5 configs
	}

	// Try to get the NCM config (config 5 on iOS devices)
	cfg, err := tryNCMConfig(device, serial)
	if err != nil {
		return err
	}
	defer closeWithLog("config "+serial, cfg.Close)
	slog.Info("got config", slog.String("config", cfg.String()), "serial", serial)

	var ifNumber = -1
	var altS = -1
	for _, iface := range cfg.Desc.Interfaces {
		for _, alt := range iface.AltSettings {
			if alt.Class == 10 && alt.SubClass == 0 && len(alt.Endpoints) == 2 {
				slog.Info("alt setting", slog.String("alt", alt.String()), slog.Int("class", int(alt.Class)), slog.Int("subclass", int(alt.SubClass)), slog.String("protocol", alt.Protocol.String()), slog.String("serial", serial))
				ifNumber = iface.Number
				altS = alt.Alternate
			}
		}
	}
	if ifNumber == -1 || altS == -1 {
		return fmt.Errorf("handleDevice: could not find interface or altsetting")
	}
	iface, err := cfg.Interface(ifNumber, altS)
	if err != nil {
		return fmt.Errorf("handleDevice: failed to claim interface for device %s. this can happen if some other process already claimed it. err %w", serial, err)
	}
	defer func() {
		slog.Info("closing interface", "serial", serial)
		iface.Close()
	}()
	var inEndpoint = -1
	var outEndpoint = -1
	var inDesc gousb.EndpointDesc
	for endpoint, i := range iface.Setting.Endpoints {
		slog.Info(endpoint.String())
		if i.Direction == gousb.EndpointDirectionIn {
			inEndpoint = i.Number
			inDesc = i
		}
		if i.Direction == gousb.EndpointDirectionOut {
			outEndpoint = i.Number
		}
	}
	if inEndpoint == -1 {
		return fmt.Errorf("handleDevice: failed to find in-endpoint for device %s", serial)
	}
	if outEndpoint == -1 {
		return fmt.Errorf("handleDevice: failed to find out-endpoint for device %s", serial)
	}

	in, err := iface.InEndpoint(inEndpoint)
	if err != nil {
		return fmt.Errorf("handleDevice: failed to open in-endpoint for device %s with err %w", serial, err)
	}

	out, err := iface.OutEndpoint(outEndpoint)
	if err != nil {
		return fmt.Errorf("handleDevice: failed to open out-endpoint for device %s with err %w", serial, err)
	}
	slog.Info("claimed interfaces", "serial", serial)

	inStream, err := in.NewStream(inDesc.MaxPacketSize*3, 1)
	if err != nil {
		return fmt.Errorf("handleDevice: failed to open in-stream for device %s with err %w", serial, err)
	}
	defer closeWithLog("in stream", inStream.Close)

	slog.Info("created streams", "serial", serial)

	ifce, err := createConfig(serial)
	if err != nil {
		return fmt.Errorf("handleDevice: failed to create config for device %s with err %w", serial, err)
	}
	defer closeWithLog("virtual TAP interface", ifce.Close)

	//blocks until the device disconnects or the adapter fails for some reason
	err = ncmIOCopy(out, inStream, ifce, serial)
	slog.Info("stopping interface for device", "serial", serial)
	
	// Device disconnected or failed - remove from tracking so it can be re-handled
	allocatedDevices.Delete(serial)
	failedDevices.Delete(serial) // Clear any failed state
	
	if err != nil {
		slog.Error("failed to copy data", "err", err, "serial", serial)
	}
	return err
}

func closeWithLog(msg string, closeable func() error) {
	slog.Info("closing", "what", msg)
	err := closeable()
	if err != nil {
		slog.Error("failed closing", "err", err)
	}
}

func createConfig(serial string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = interfaceName(serial)
	slog.Info("creating TAP device", "device", config.Name, "serial", serial)
	ifce, err := water.New(config)
	if err != nil {
		return &water.Interface{}, fmt.Errorf("createConfig: failed creating ifce %w", err)
	}
	hasIp, output := InterfaceHasIP(config.Name)
	if !hasIp {
		ip := "FC00:0000:0000:0000:0000:0000:0000:00FB/64"
		slog.Info("add IP address to device", "device", config.Name, "serial", serial, "ip", ip)
		output, err := AddInterface(config.Name, ip)
		if err != nil {
			return &water.Interface{}, fmt.Errorf("createConfig: err adding ip to interface. cmd output: '%s' err: %w", output, err)
		}
	} else {
		slog.Info("ip found", "interface", config.Name, "ip", output)
	}

	output, err = SetInterfaceUp(config.Name)
	if err != nil {
		return &water.Interface{}, fmt.Errorf("createConfig: err calling interface up. cmd output: '%s' err: %w", output, err)
	}
	slog.Info("ethernet device is up:", "device", config.Name, "serial", serial)

	return ifce, err
}

// ncmIOCopy copies data between a USB device and a virtual network interface. It is blocking until the connection fails
// for some reason. This happens if the device is disconnected or if the virtual network interface is removed.
// Closing interfaces is the responsibility of the caller.
func ncmIOCopy(w io.Writer, r io.Reader, ifce *water.Interface, serial string) error {
	wr := NewWrapper(r, w, serial)
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		var frame ethernet.Frame
		for {
			select {
			case <-ctx.Done():
				return
			default:
				frame.Resize(1500)
				n, err := ifce.Read([]byte(frame))
				if err != nil {
					slog.Error("ncmIOCopy: failed to read from iface", slog.Any("error", err), slog.String("serial", serial))
					cancel()
					continue
				}
				networkReceiveBytes.WithLabelValues(ifce.Name(), serial).Add(float64(n))
				frame = frame[:n]
				_, err = wr.Write(frame)
				if err != nil {
					slog.Error("ncmIOCopy: failed to copy from iface to usb", slog.Any("error", err), slog.String("serial", serial))
					cancel()
				}
			}
		}

	}()

	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				frames, err := wr.ReadDatagrams()
				if err != nil {
					slog.Error("ncmIOCopy: failed to read from usb", slog.Any("error", err), slog.String("serial", serial))
					cancel()
					continue
				}
				for _, frame := range frames {
					_, err := ifce.Write(frame)
					if err != nil {
						slog.Error("failed sending frame to virtual device", "err", err)
						cancel()
					}
					networkSendBytes.WithLabelValues(ifce.Name(), serial).Add(float64(len(frame)))
				}
			}
		}
	}()
	wg.Wait()

	return nil
}
