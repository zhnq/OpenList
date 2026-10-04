package xiaomi

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Username          string `json:"username" required:"true" help:"Xiaomi account (phone, email or account ID)"`
	Password          string `json:"password" help:"Account password; leave empty to retain the saved credential"`
	SendSMS           bool   `json:"send_sms" help:"Only enable when phone verification is required, then save to send a code"`
	SMSCode           string `json:"sms_code" help:"Enter the SMS code and save; the verified device will be remembered"`
	DeviceID          string `json:"device_id" help:"Generated automatically and reused; changing it may require verification"`
	DeviceFingerprint string `json:"device_fingerprint" help:"Optional existing browser fingerprint; retained automatically"`
	Session           string `json:"session" ignore:"true"`
	PasswordHash      string `json:"password_hash" ignore:"true"`
}

var config = driver.Config{
	Name: "Xiaomi Cloud Recordings", LocalSort: true, NoUpload: true,
	OnlyProxy: true, NoLinkURL: true, CheckStatus: true, DefaultRoot: "0",
	Alert: "info|Read-only recordings already synced to Xiaomi Cloud. Device trust and tokens are saved automatically. If phone verification is requested, enable Send SMS and save, then enter the code and save again.",
}

func init() {
	op.RegisterDriver(func() driver.Driver { return &Xiaomi{} })
}
