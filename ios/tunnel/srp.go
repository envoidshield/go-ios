package tunnel

import (
	"crypto/sha512"
	"fmt"
  log "github.com/sirupsen/logrus"
	"github.com/tadglines/go-pkgs/crypto/srp"
  "encoding/hex"
)

type srpInfo struct {
	ClientPublic []byte
	ClientProof  []byte
	Salt         []byte
	SessionKey   []byte
	c            *srp.ClientSession
}

// newSrpInfo initializes a new SRP session with the given public key and salt values.
func newSrpInfo(salt, publicKey []byte) (srpInfo, error) {
  log.Debug("Initializing SRP with rfc5054.3072 and sha512")
	s, err := srp.NewSRP("rfc5054.3072", sha512.New, func(salt, password []byte) []byte {
		h1 := sha512.New()
		h2 := sha512.New()
		h2.Write([]byte(fmt.Sprintf("%s:%s", "Pair-Setup", string(password))))
		h1.Write(salt)
		h1.Write(h2.Sum(nil))
		return h1.Sum(nil)
	})
	if err != nil {
		log.WithError(err).Error("Failed to initialize SRP")
		return srpInfo{}, fmt.Errorf("newSrpInfo: failed to initialize SRP: %w", err)
	}
	log.Debug("SRP initialized successfully")

	log.Debug("Creating SRP client session with username='Pair-Setup' and password='000000'")
	c := s.NewClientSession([]byte("Pair-Setup"), []byte("000000"))
	if c == nil {
		log.Error("Client session creation returned nil")
		return srpInfo{}, fmt.Errorf("newSrpInfo: failed to create client session")
	}
	log.Debug("SRP client session created successfully")

	log.Debug("Computing session key")
	key, err := c.ComputeKey(salt, publicKey)
	if err != nil {
		log.WithError(err).Error("Failed to compute session key")
		return srpInfo{}, fmt.Errorf("newSrpInfo: failed to compute session key: %w", err)
	}
	log.Debugf("Session key computed: %s", hex.EncodeToString(key))

	a := c.ComputeAuthenticator()
	log.Debugf("Client public key (A): %s", hex.EncodeToString(c.GetA()))
	log.Debugf("Client proof: %s", hex.EncodeToString(a))

	return srpInfo{
		ClientPublic: c.GetA(),
		ClientProof:  a,
		Salt:         salt,
		SessionKey:   key,
		c:            c,
	}, nil

}

func (s srpInfo) verifyServerProof(p []byte) bool {
  log.Debug("compute the SRP shered secret")
	return s.c.VerifyServerAuthenticator(p)
}
