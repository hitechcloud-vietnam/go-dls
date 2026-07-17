package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ── constants ─────────────────────────────────────────────────────────────────

const (
	siteKeyXID   = "00000000-0000-0000-0000-000000000000"
	allotmentRef = "20000000-0000-0000-0000-000000000001"
)

// ── globals ───────────────────────────────────────────────────────────────────

var (
	cfg Config
	db  *DB
	km  *KeyManager
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	DLSURL             string
	DLSPort            string
	LeaseExpireDays    int
	LeaseRenewalPeriod float64
	TokenExpireDays    int
	DBDSN              string
	CertDir            string
}

func loadConfig() Config {
	return Config{
		DLSURL:             getEnv("DLS_URL", "localhost"),
		DLSPort:            getEnv("DLS_PORT", "443"),
		LeaseExpireDays:    getEnvInt("LEASE_EXPIRE_DAYS", 90),
		LeaseRenewalPeriod: getEnvFloat("LEASE_RENEWAL_PERIOD", 0.15),
		TokenExpireDays:    getEnvInt("TOKEN_EXPIRE_DAYS", 1),
		DBDSN:              getEnv("DB_DSN", "/app/db/db.sqlite"),
		CertDir:            getEnv("CERT_DIR", "/app/cert"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

// ── crypto ────────────────────────────────────────────────────────────────────

type KeyManager struct {
	PrivateKey *rsa.PrivateKey
}

func loadOrCreateKeys(dir string) (*KeyManager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	privPath := filepath.Join(dir, "instance.private.pem")
	pubPath := filepath.Join(dir, "instance.public.pem")

	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		if err := generateSelfSigned(privPath, pubPath); err != nil {
			return nil, fmt.Errorf("generate keys: %w", err)
		}
	}

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privPEM)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &KeyManager{PrivateKey: privKey}, nil
}

func generateSelfSigned(privPath, pubPath string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cfg.DLSURL},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(cfg.DLSURL); ip != nil {
		tmpl.IPAddresses = []net.IP{ip, net.IPv4(127, 0, 0, 1)}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.DNSNames = []string{cfg.DLSURL, "localhost"}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	privFile, err := os.OpenFile(privPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privFile.Close()
	pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	pubFile, err := os.OpenFile(pubPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer pubFile.Close()
	pem.Encode(pubFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return nil
}

func (km *KeyManager) signJWT(claims any) (string, error) {
	hdr := b64json(map[string]string{"alg": "RS256", "typ": "JWT"})
	pay := b64json(claims)
	msg := hdr + "." + pay
	h := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, km.PrivateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (km *KeyManager) parseJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if err := rsa.VerifyPKCS1v15(&km.PrivateKey.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		return nil, err
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payBytes, &claims); err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return nil, errors.New("token expired")
	}
	return claims, nil
}

// instanceRef derives a stable UUID from the RSA public key fingerprint.
func (km *KeyManager) instanceRef() string {
	der, _ := x509.MarshalPKIXPublicKey(&km.PrivateKey.PublicKey)
	h := sha256.Sum256(der)
	h[6] = (h[6] & 0x0f) | 0x40
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// pubKeyME returns {mod: hex(N), exp: E} matching the original DLS format.
func (km *KeyManager) pubKeyME() map[string]any {
	pub := &km.PrivateKey.PublicKey
	return map[string]any{
		"mod": fmt.Sprintf("%x", pub.N),
		"exp": pub.E,
	}
}

// pubKeyPEM returns raw PEM string of the public key.
func (km *KeyManager) pubKeyPEM() string {
	der, _ := x509.MarshalPKIXPublicKey(&km.PrivateKey.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newUUID() string {
	var b [16]byte
	io.ReadFull(rand.Reader, b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ── database ──────────────────────────────────────────────────────────────────

type DB struct{ *sql.DB }

func openDB(dsn string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dsn), 0755); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS origins (
			origin_ref           TEXT PRIMARY KEY,
			hostname             TEXT,
			guest_driver_version TEXT,
			os_platform          TEXT,
			os_version           TEXT,
			created_at           DATETIME,
			updated_at           DATETIME
		);
		CREATE TABLE IF NOT EXISTS leases (
			lease_ref  TEXT PRIMARY KEY,
			origin_ref TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
	`)
	if err != nil {
		return nil, err
	}
	return &DB{conn}, nil
}

type Origin struct {
	OriginRef          string `json:"origin_ref"`
	Hostname           string `json:"hostname"`
	GuestDriverVersion string `json:"guest_driver_version"`
	OSPlatform         string `json:"os_platform"`
	OSVersion          string `json:"os_version"`
}

type Lease struct {
	LeaseRef  string    `json:"lease_ref"`
	OriginRef string    `json:"origin_ref"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (db *DB) upsertOrigin(o *Origin) error {
	_, err := db.Exec(`
		INSERT INTO origins(origin_ref, hostname, guest_driver_version, os_platform, os_version, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(origin_ref) DO UPDATE SET
			hostname=excluded.hostname,
			guest_driver_version=excluded.guest_driver_version,
			os_platform=excluded.os_platform,
			os_version=excluded.os_version,
			updated_at=excluded.updated_at`,
		o.OriginRef, o.Hostname, o.GuestDriverVersion, o.OSPlatform, o.OSVersion,
		time.Now().UTC(), time.Now().UTC())
	return err
}

func (db *DB) createLease(l *Lease) error {
	l.LeaseRef = newUUID()
	_, err := db.Exec(`INSERT INTO leases VALUES (?,?,?,?,?)`,
		l.LeaseRef, l.OriginRef, l.CreatedAt, l.ExpiresAt, l.UpdatedAt)
	return err
}

func (db *DB) findLease(leaseRef string) (*Lease, error) {
	l := &Lease{}
	err := db.QueryRow(`SELECT lease_ref, origin_ref, created_at, expires_at, updated_at FROM leases WHERE lease_ref=?`, leaseRef).
		Scan(&l.LeaseRef, &l.OriginRef, &l.CreatedAt, &l.ExpiresAt, &l.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (db *DB) leasesByOrigin(originRef string) ([]string, error) {
	rows, err := db.Query(`SELECT lease_ref FROM leases WHERE origin_ref=?`, originRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ref string
		rows.Scan(&ref)
		out = append(out, ref)
	}
	return out, nil
}

func (db *DB) renewLease(leaseRef string, expiresAt, updatedAt time.Time) error {
	_, err := db.Exec(`UPDATE leases SET expires_at=?, updated_at=? WHERE lease_ref=?`,
		expiresAt, updatedAt, leaseRef)
	return err
}

func (db *DB) deleteLease(leaseRef string) error {
	_, err := db.Exec(`DELETE FROM leases WHERE lease_ref=?`, leaseRef)
	return err
}

func (db *DB) purgeExpiredLeases() {
	db.Exec(`DELETE FROM leases WHERE expires_at <= ?`, time.Now().UTC())
}

func (db *DB) allOrigins() ([]Origin, error) {
	rows, err := db.Query(`SELECT origin_ref, hostname, guest_driver_version, os_platform, os_version FROM origins`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Origin{}
	for rows.Next() {
		var o Origin
		rows.Scan(&o.OriginRef, &o.Hostname, &o.GuestDriverVersion, &o.OSPlatform, &o.OSVersion)
		out = append(out, o)
	}
	return out, nil
}

func (db *DB) allLeases() ([]Lease, error) {
	rows, err := db.Query(`SELECT lease_ref, origin_ref, created_at, expires_at, updated_at FROM leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Lease{}
	for rows.Next() {
		var l Lease
		rows.Scan(&l.LeaseRef, &l.OriginRef, &l.CreatedAt, &l.ExpiresAt, &l.UpdatedAt)
		out = append(out, l)
	}
	return out, nil
}

// ── http helpers ──────────────────────────────────────────────────────────────

type ctxKey string

const ctxOriginRef ctxKey = "origin_ref"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeSignedJSON(w http.ResponseWriter, status int, v any) {
	body, _ := json.Marshal(v)
	body = append(body, '\n')
	h := sha256.Sum256(body)
	sig, err := rsa.SignPKCS1v15(rand.Reader, km.PrivateKey, crypto.SHA256, h[:])
	if err == nil {
		w.Header().Set("x-nls-signature", fmt.Sprintf("b'%s'", fmt.Sprintf("%x", sig)))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func withJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}
		claims, err := km.parseJWT(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		originRef, _ := claims["origin_ref"].(string)
		if originRef == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing origin_ref"})
			return
		}
		ctx := context.WithValue(r.Context(), ctxOriginRef, originRef)
		next(w, r.WithContext(ctx))
	}
}

func originRefFrom(r *http.Request) string {
	v, _ := r.Context().Value(ctxOriginRef).(string)
	return v
}

func utcNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ── auth handlers ─────────────────────────────────────────────────────────────

func handleOrigin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CandidateOriginRef string `json:"candidate_origin_ref"`
		Environment        struct {
			Hostname           string `json:"hostname"`
			GuestDriverVersion string `json:"guest_driver_version"`
			OSPlatform         string `json:"os_platform"`
			OSVersion          string `json:"os_version"`
		} `json:"environment"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	db.upsertOrigin(&Origin{
		OriginRef:          req.CandidateOriginRef,
		Hostname:           req.Environment.Hostname,
		GuestDriverVersion: req.Environment.GuestDriverVersion,
		OSPlatform:         req.Environment.OSPlatform,
		OSVersion:          req.Environment.OSVersion,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"origin_ref":      req.CandidateOriginRef,
		"environment":     req.Environment,
		"svc_port_set_list": nil,
		"node_url_list":   nil,
		"node_query_order": nil,
		"prompts":         nil,
		"sync_timestamp":  utcNow(),
	})
}

func handleCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OriginRef     string `json:"origin_ref"`
		CodeChallenge string `json:"code_challenge"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	authCode, err := km.signJWT(map[string]any{
		"iat":        now.Unix(),
		"exp":        now.Add(15 * time.Minute).Unix(),
		"challenge":  req.CodeChallenge,
		"origin_ref": req.OriginRef,
		"key_ref":    siteKeyXID,
		"kid":        siteKeyXID,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_code":      authCode,
		"sync_timestamp": utcNow(),
		"prompts":        nil,
	})
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthCode     string `json:"auth_code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	claims, err := km.parseJWT(req.AuthCode)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "400", "title": "invalid token", "detail": err.Error()})
		return
	}
	// PKCE: challenge = base64(sha256(verifier)), padding stripped — RFC 7636
	h := sha256.Sum256([]byte(req.CodeVerifier))
	challenge := base64.StdEncoding.EncodeToString(h[:])
	challenge = strings.TrimRight(challenge, "=")
	if claims["challenge"] != challenge {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"status": "401", "detail": "expected challenge did not match verifier"})
		return
	}
	originRef, _ := claims["origin_ref"].(string)
	now := time.Now().UTC()
	expires := now.AddDate(0, 0, cfg.TokenExpireDays)
	accessToken, err := km.signJWT(map[string]any{
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"iss":        "https://cls.nvidia.org",
		"aud":        "https://cls.nvidia.org",
		"exp":        expires.Unix(),
		"origin_ref": originRef,
		"key_ref":    siteKeyXID,
		"kid":        siteKeyXID,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"expires":        expires.Format(time.RFC3339),
		"auth_token":     accessToken,
		"sync_timestamp": utcNow(),
	})
}

// ── leasing handlers ──────────────────────────────────────────────────────────

func handleConfigToken(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	certPEM := km.pubKeyPEM()
	token, err := km.signJWT(map[string]any{
		"iat":              now.Unix(),
		"nbf":              now.Unix(),
		"exp":              now.Add(15 * time.Minute).Unix(),
		"protocol_version": "2.0",
		"d_name":           "DLS",
		"service_instance_ref": km.instanceRef(),
		"service_instance_public_key_configuration": map[string]any{
			"service_instance_public_key_me":  km.pubKeyME(),
			"service_instance_public_key_pem": certPEM,
			"key_retention_mode":              "LATEST_ONLY",
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certificateConfiguration": map[string]any{
			"caChain":    []string{certPEM},
			"publicCert": certPEM,
			"publicKey":  km.pubKeyME(),
		},
		"configToken": token,
	})
}

func handleLeasorReleaseAll(w http.ResponseWriter, r *http.Request) {
	originRef := originRefFrom(r)
	refs, _ := db.leasesByOrigin(originRef)
	db.Exec(`DELETE FROM leases WHERE origin_ref=?`, originRef)
	writeJSON(w, http.StatusOK, map[string]any{
		"released_lease_list":  refs,
		"release_failure_list": nil,
		"prompts":              nil,
		"sync_timestamp":       utcNow(),
	})
}

func handleLeasorCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeRefList []string `json:"scope_ref_list"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	db.purgeExpiredLeases()
	originRef := originRefFrom(r)
	now := time.Now().UTC()
	exp := now.AddDate(0, 0, cfg.LeaseExpireDays)

	results := make([]map[string]any, 0, len(req.ScopeRefList))
	for range req.ScopeRefList {
		lease := &Lease{
			OriginRef: originRef,
			CreatedAt: now,
			ExpiresAt: exp,
			UpdatedAt: now,
		}
		if err := db.createLease(lease); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db write failed"})
			return
		}
		results = append(results, map[string]any{
			"ordinal": 0,
			"lease": map[string]any{
				"ref":                       lease.LeaseRef,
				"created":                   now.Format(time.RFC3339),
				"expires":                   exp.Format(time.RFC3339),
				"recommended_lease_renewal": cfg.LeaseRenewalPeriod,
				"offline_lease":             true,
				"license_type":              "CONCURRENT_COUNTED_SINGLE",
			},
		})
	}
	writeSignedJSON(w, http.StatusOK, map[string]any{
		"lease_result_list": results,
		"result_code":       "SUCCESS",
		"sync_timestamp":    utcNow(),
		"prompts":           nil,
	})
}

func handleLeasorLeases(w http.ResponseWriter, r *http.Request) {
	originRef := originRefFrom(r)
	refs, err := db.leasesByOrigin(originRef)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_lease_list": refs,
		"sync_timestamp":    utcNow(),
		"prompts":           nil,
	})
}

func handleLeaseRenew(w http.ResponseWriter, r *http.Request) {
	leaseRef := r.PathValue("lease_ref")
	originRef := originRefFrom(r)
	lease, err := db.findLease(leaseRef)
	if err != nil || lease.OriginRef != originRef {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "404", "detail": "requested lease not available"})
		return
	}
	now := time.Now().UTC()
	exp := now.AddDate(0, 0, cfg.LeaseExpireDays)
	db.renewLease(leaseRef, exp, now)
	writeSignedJSON(w, http.StatusOK, map[string]any{
		"lease_ref":                 leaseRef,
		"expires":                   exp.Format(time.RFC3339),
		"recommended_lease_renewal": cfg.LeaseRenewalPeriod,
		"offline_lease":             true,
		"prompts":                   nil,
		"sync_timestamp":            utcNow(),
	})
}

func handleLeasorShutdown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	claims, err := km.parseJWT(req.Token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	originRef, _ := claims["origin_ref"].(string)
	db.Exec(`DELETE FROM leases WHERE origin_ref=?`, originRef)
	writeJSON(w, http.StatusOK, map[string]any{
		"sync_timestamp": utcNow(),
		"prompts":        nil,
	})
}

func handleLeaseDelete(w http.ResponseWriter, r *http.Request) {
	leaseRef := r.PathValue("lease_ref")
	originRef := originRefFrom(r)
	lease, err := db.findLease(leaseRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "404", "detail": "requested lease not available"})
		return
	}
	if lease.OriginRef != originRef {
		writeJSON(w, http.StatusForbidden, map[string]string{"status": "403", "detail": "access or operation forbidden"})
		return
	}
	db.deleteLease(leaseRef)
	writeJSON(w, http.StatusOK, map[string]any{
		"lease_ref":      leaseRef,
		"prompts":        nil,
		"sync_timestamp": utcNow(),
	})
}

// ── admin handlers ────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "up"})
}

// svcPort must be a struct (not map) so json.Marshal preserves field order.
// nvidia-gridd parses svc_port_map by index, not by key name.
type svcPort struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
}

func handleClientToken(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	portNum, _ := strconv.Atoi(cfg.DLSPort)
	token, err := km.signJWT(map[string]any{
		"jti":                        newUUID(),
		"iss":                        "NLS Service Instance",
		"aud":                        "NLS Licensed Client",
		"iat":                        now.Unix(),
		"nbf":                        now.Unix(),
		"exp":                        now.AddDate(12, 0, 0).Unix(),
		"update_mode":                "ABSOLUTE",
		"scope_ref_list":             []string{allotmentRef},
		"fulfillment_class_ref_list": []string{},
		"service_instance_configuration": map[string]any{
			"nls_service_instance_ref": km.instanceRef(),
			"svc_port_set_list": []map[string]any{{
				"idx":    0,
				"d_name": "DLS",
				"svc_port_map": []svcPort{
					{Service: "auth", Port: portNum},
					{Service: "lease", Port: portNum},
				},
			}},
			"node_url_list": []map[string]any{{
				"idx":              0,
				"url":              cfg.DLSURL,
				"url_qr":           cfg.DLSURL,
				"svc_port_set_idx": 0,
			}},
		},
		"service_instance_public_key_configuration": map[string]any{
			"service_instance_public_key_me":  km.pubKeyME(),
			"service_instance_public_key_pem": km.pubKeyPEM(),
			"key_retention_mode":              "LATEST_ONLY",
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	filename := fmt.Sprintf("client_configuration_token_%s.tok", time.Now().Format("02-01-06-15-04-05"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write([]byte(token))
}

func handleListOrigins(w http.ResponseWriter, _ *http.Request) {
	origins, _ := db.allOrigins()
	writeJSON(w, http.StatusOK, origins)
}

func handleDeleteOrigins(w http.ResponseWriter, _ *http.Request) {
	db.Exec(`DELETE FROM origins`)
	db.Exec(`DELETE FROM leases`)
	w.WriteHeader(http.StatusNoContent)
}

func handleListLeases(w http.ResponseWriter, _ *http.Request) {
	db.purgeExpiredLeases()
	leases, _ := db.allLeases()
	writeJSON(w, http.StatusOK, leases)
}

func handleDeleteOrigin(w http.ResponseWriter, r *http.Request) {
	originRef := r.PathValue("origin_ref")
	db.Exec(`DELETE FROM leases WHERE origin_ref=?`, originRef)
	db.Exec(`DELETE FROM origins WHERE origin_ref=?`, originRef)
	w.WriteHeader(http.StatusNoContent)
}

func handleDeleteLease(w http.ResponseWriter, r *http.Request) {
	if err := db.deleteLease(r.PathValue("lease_ref")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleManage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(manageHTML))
}

const manageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>go-dls</title>
<style>
  body { font-family: monospace; padding: 2rem; max-width: 900px; margin: 0 auto; }
  h2 { font-size: 0.9rem; margin: 1.5rem 0 0.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td { text-align: left; padding: 0.3rem 0.5rem; border-bottom: 1px solid #ddd; }
  th { color: #666; }
  button { font-size: 0.75rem; cursor: pointer; padding: 0.1rem 0.4rem; }
  .top { display: flex; justify-content: space-between; align-items: center; }
  .empty { color: #999; font-size: 0.8rem; padding: 0.5rem; }
</style>
</head>
<body>
<div class="top">
  <strong>go-dls</strong>
  <span>
    <span id="status-text">...</span> &nbsp;
    <a href="/-/client-token">download .tok</a> &nbsp;
    <button onclick="deleteAllOrigins()">delete all origins</button>
  </span>
</div>
<h2>Origins (<span id="origin-count">0</span>)</h2>
<table>
  <thead><tr><th>Hostname</th><th>Driver</th><th>OS</th><th></th></tr></thead>
  <tbody id="origins-body"></tbody>
</table>
<h2>Leases (<span id="lease-count">0</span>)</h2>
<table>
  <thead><tr><th>Lease Ref</th><th>Origin</th><th>Expires</th><th></th></tr></thead>
  <tbody id="leases-body"></tbody>
</table>
<script>
async function api(method, path) {
  const r = await fetch(path, { method });
  return r.ok ? (r.status === 204 ? null : r.json()) : null;
}
function fmt(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleDateString() + ' ' + d.toTimeString().slice(0, 5);
}
function cell(text, cls) {
  const td = document.createElement('td');
  if (cls) td.className = cls;
  td.textContent = text || '-';
  return td;
}
function actionBtn(label, cls, onClick) {
  const td = document.createElement('td');
  const btn = document.createElement('button');
  btn.className = 'btn ' + cls;
  btn.textContent = label;
  btn.onclick = onClick;
  td.appendChild(btn);
  return td;
}
function emptyRow(cols, msg) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = cols;
  td.className = 'empty';
  td.textContent = msg;
  tr.appendChild(td);
  return tr;
}
async function loadOrigins() {
  const data = await api('GET', '/-/origins') || [];
  document.getElementById('origin-count').textContent = data.length;
  const tbody = document.getElementById('origins-body');
  tbody.replaceChildren();
  if (!data.length) { tbody.appendChild(emptyRow(4, 'No origins')); return; }
  data.forEach(o => {
    const tr = document.createElement('tr');
    tr.appendChild(cell(o.hostname));
    tr.appendChild(cell(o.guest_driver_version ? o.guest_driver_version.split('.')[0] : null, 'mono'));
    tr.appendChild(cell(o.os_platform));
    tr.appendChild(actionBtn('x', 'btn-ghost', () => deleteOrigin(o.origin_ref)));
    tbody.appendChild(tr);
  });
}
async function loadLeases() {
  const data = await api('GET', '/-/leases') || [];
  document.getElementById('lease-count').textContent = data.length;
  const tbody = document.getElementById('leases-body');
  tbody.replaceChildren();
  if (!data.length) { tbody.appendChild(emptyRow(4, 'No leases')); return; }
  data.forEach(l => {
    const tr = document.createElement('tr');
    tr.appendChild(cell(l.lease_ref ? l.lease_ref.slice(0, 8) + '...' : null, 'mono'));
    tr.appendChild(cell(l.origin_ref ? l.origin_ref.slice(0, 8) + '...' : null, 'mono'));
    tr.appendChild(cell(fmt(l.expires_at)));
    tr.appendChild(actionBtn('x', 'btn-danger', () => deleteLease(l.lease_ref)));
    tbody.appendChild(tr);
  });
}
async function checkHealth() {
  const r = await fetch('/-/health').catch(() => null);
  const ok = r && r.ok;
  const dot = document.getElementById('dot');
  dot.style.background = ok ? '#4ade80' : '#f87171';
  dot.style.boxShadow = ok ? '0 0 6px #4ade80' : '0 0 6px #f87171';
  document.getElementById('status-text').textContent = ok ? 'online' : 'offline';
}
async function deleteAllOrigins() {
  if (!confirm('Delete all origins and leases?')) return;
  await api('DELETE', '/-/origins');
  load();
}
async function deleteOrigin(ref) {
  await api('DELETE', '/-/origins/' + ref);
  load();
}
async function deleteLease(ref) {
  await api('DELETE', '/-/lease/' + ref);
  loadLeases();
}
function downloadToken() { window.location.href = '/-/client-token'; }
function load() { loadOrigins(); loadLeases(); }
checkHealth();
load();
setInterval(load, 30000);
</script>
</body>
</html>`

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	cfg = loadConfig()

	var err error
	db, err = openDB(cfg.DBDSN)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	km, err = loadOrCreateKeys(cfg.CertDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/v1/origin", handleOrigin)
	mux.HandleFunc("POST /auth/v1/origin/update", handleOrigin)
	mux.HandleFunc("POST /auth/v1/code", handleCode)
	mux.HandleFunc("POST /auth/v1/token", handleToken)

	mux.HandleFunc("POST /leasing/v1/config-token", handleConfigToken)
	mux.HandleFunc("POST /leasing/v1/lessor", withJWT(handleLeasorCreate))
	mux.HandleFunc("POST /leasing/v1/lessor/shutdown", handleLeasorShutdown)
	mux.HandleFunc("GET /leasing/v1/lessor/leases", withJWT(handleLeasorLeases))
	mux.HandleFunc("DELETE /leasing/v1/lessor/leases", withJWT(handleLeasorReleaseAll))
	mux.HandleFunc("PUT /leasing/v1/lease/{lease_ref}", withJWT(handleLeaseRenew))
	mux.HandleFunc("DELETE /leasing/v1/lease/{lease_ref}", withJWT(handleLeaseDelete))

	mux.HandleFunc("GET /-/health", handleHealth)
	mux.HandleFunc("GET /-/manage", handleManage)
	mux.HandleFunc("GET /-/client-token", handleClientToken)
	mux.HandleFunc("GET /-/origins", handleListOrigins)
	mux.HandleFunc("DELETE /-/origins", handleDeleteOrigins)
	mux.HandleFunc("DELETE /-/origins/{origin_ref}", handleDeleteOrigin)
	mux.HandleFunc("GET /-/leases", handleListLeases)
	mux.HandleFunc("DELETE /-/lease/{lease_ref}", handleDeleteLease)

	srv := &http.Server{
		Addr:      ":" + cfg.DLSPort,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	certFile := filepath.Join(cfg.CertDir, "instance.public.pem")
	keyFile := filepath.Join(cfg.CertDir, "instance.private.pem")

	log.Printf("DLS listening on :%s", cfg.DLSPort)
	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}
