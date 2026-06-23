package ios

import "fmt"

type SavePair struct {
	BundleID            string
	ClientVersionString string
	MessageType         string
	ProgName            string
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
	PairRecordID        string
	PairRecordData      []byte
}

type savePairRecordData struct {
	DeviceCertificate []byte
	HostPrivateKey    []byte
	HostCertificate   []byte
	RootPrivateKey    []byte
	RootCertificate   []byte
	EscrowBag         []byte
	WiFiMACAddress    string
	HostID            string
	SystemBUID        string
}

func newSavePair(udid string, savePairRecordData []byte) SavePair {
	data := SavePair{
		BundleID:            "go.ios.control",
		ClientVersionString: "go-ios-1.0.0",
		MessageType:         "SavePairRecord",
		ProgName:            "go-ios",
		LibUSBMuxVersion:    3,
		PairRecordID:        udid,
		PairRecordData:      savePairRecordData,
	}
	return data
}

func newSavePairRecordData(DeviceCertificate []byte,
	HostPrivateKey []byte,
	HostCertificate []byte,
	RootPrivateKey []byte,
	RootCertificate []byte,
	EscrowBag []byte,
	WiFiMACAddress string,
	HostID string,
	SystemBUID string,
) []byte {
	result := savePairRecordData{DeviceCertificate, HostPrivateKey, HostCertificate, RootPrivateKey, RootCertificate, EscrowBag, WiFiMACAddress, HostID, SystemBUID}
	bytes := []byte(ToPlist(result))
	return bytes
}

// SavePairRecord persists a USB lockdown pair record with usbmuxd.
func SavePairRecord(udid string, record PairRecord) error {
	muxConn, err := NewUsbMuxConnectionSimple()
	if err != nil {
		return err
	}
	defer muxConn.Close()
	ok, err := muxConn.savePair(
		udid,
		record.DeviceCertificate,
		record.HostPrivateKey,
		record.HostCertificate,
		record.RootPrivateKey,
		record.RootCertificate,
		record.EscrowBag,
		record.WiFiMACAddress,
		record.HostID,
		record.SystemBUID,
	)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("usbmux SavePairRecord failed for %s", udid)
	}
	return nil
}

func (muxConn *UsbMuxConnection) savePair(udid string, DeviceCertificate []byte,
	HostPrivateKey []byte,
	HostCertificate []byte,
	RootPrivateKey []byte,
	RootCertificate []byte,
	EscrowBag []byte,
	WiFiMACAddress string,
	HostID string,
	SystemBUID string,
) (bool, error) {
	bytes := newSavePairRecordData(DeviceCertificate, HostPrivateKey, HostCertificate, RootPrivateKey, RootCertificate, EscrowBag, WiFiMACAddress, HostID, SystemBUID)
	err := muxConn.Send(newSavePair(udid, bytes))
	if err != nil {
		return false, err
	}
	resp, err := muxConn.ReadMessage()
	if err != nil {
		return false, err
	}
	muxresponse := MuxResponsefromBytes(resp.Payload)
	return muxresponse.IsSuccessFull(), nil
}
