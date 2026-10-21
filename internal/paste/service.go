package paste

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/venkatvghub/privatebin-go/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// SchemaVersion is the PrivateBin release whose schema we mirror.
const SchemaVersion = "2.1.0"

var (
	ErrNotFound   = errors.New("paste not found")
	ErrWrongToken = errors.New("wrong deletion token")
)

// Expiries maps the PrivateBin expire keys to durations. Zero means never.
var Expiries = map[string]time.Duration{
	"5min":   5 * time.Minute,
	"10min":  10 * time.Minute,
	"1hour":  time.Hour,
	"1day":   24 * time.Hour,
	"1week":  7 * 24 * time.Hour,
	"1month": 30 * 24 * time.Hour,
	"1year":  365 * 24 * time.Hour,
	"never":  0,
}

// migrateLockID is an arbitrary application-wide advisory lock key.
const migrateLockID = 7260211

var prefixRe = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

type Service struct {
	db   *gorm.DB
	salt []byte
}

// NamingStrategy returns the gorm naming strategy matching PrivateBin's
// optional table prefix (config option "tbl").
func NamingStrategy(prefix string) schema.NamingStrategy {
	return schema.NamingStrategy{TablePrefix: prefix, SingularTable: true}
}

// New creates the service. salt keys the delete tokens: HMAC-SHA256(salt, id),
// the same construction PrivateBin uses, so it must equal PrivateBin's server
// salt to honour tokens issued by it.
func New(db *gorm.DB, salt string) *Service { return &Service{db: db, salt: []byte(salt)} }

// Migrate creates the PrivateBin 2.1.0 tables if absent, with the same DDL
// PrivateBin uses on PostgreSQL. Existing tables are left untouched.
func (s *Service) Migrate(prefix string) error {
	if !prefixRe.MatchString(prefix) {
		return fmt.Errorf("invalid table prefix %q", prefix)
	}
	t := func(name string) string { return `"` + prefix + name + `"` }
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s ("dataid" CHAR(16) NOT NULL PRIMARY KEY, "data" TEXT, "expiredate" INT, "meta" TEXT)`, t("paste")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s ("dataid" CHAR(16) NOT NULL PRIMARY KEY, "pasteid" CHAR(16), "parentid" CHAR(16), "data" TEXT, "vizhash" TEXT, "postdate" INT)`, t("comment")),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s ("pasteid")`, t("comment_parent"), t("comment")),
		// Not in PrivateBin (which ignores it): keeps the purge scan cheap.
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s ("expiredate")`, t("paste_expiredate"), t("paste")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s ("id" CHAR(16) NOT NULL PRIMARY KEY, "value" TEXT)`, t("config")),
		fmt.Sprintf(`INSERT INTO %s VALUES ('VERSION', '%s') ON CONFLICT DO NOTHING`, t("config"), SchemaVersion),
	}
	// CREATE ... IF NOT EXISTS is not safe against concurrent runs (two replicas,
	// or parallel test packages), so serialise migrations with an advisory lock.
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(?)`, migrateLockID).Error; err != nil {
			return err
		}
		for _, q := range stmts {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// deleteToken is HMAC-SHA256(salt, id) in hex.
func (s *Service) deleteToken(id string) string {
	m := hmac.New(sha256.New, s.salt)
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))
}

// Create validates and stores a paste. It returns the id, the delete token and
// whether the paste is burn-after-reading. Unknown or missing expiry keys fall
// back to one week, as in PrivateBin.
func (s *Service) Create(in *Input) (id, token string, burn bool, err error) {
	if burn, err = in.Validate(); err != nil {
		return
	}
	exp, ok := Expiries[in.Meta.Expire]
	if !ok {
		exp = Expiries["1week"]
	}
	data, _ := json.Marshal(stored{V: 2, AData: in.AData, CT: json.RawMessage(strconv.Quote(in.CT))})
	id, token, err = s.insert(string(data), exp)
	return
}

func (s *Service) insert(data string, expire time.Duration) (id, deleteToken string, err error) {
	if id, err = newID(); err != nil {
		return
	}
	now := time.Now()
	p := model.Paste{DataID: id, Data: data, Meta: fmt.Sprintf(`{"created":%d}`, now.Unix())}
	if expire > 0 {
		p.ExpireDate = now.Add(expire).Unix()
	}
	return id, s.deleteToken(id), s.db.Create(&p).Error
}

// stored is the JSON kept in paste.data.
type stored struct {
	V     int             `json:"v"`
	AData json.RawMessage `json:"adata"`
	CT    json.RawMessage `json:"ct"`
}

// View is a paste as returned to clients.
type View struct {
	ID         string
	Stored     stored
	Created    int64
	TimeToLive *int64 // seconds left; nil when the paste never expires
	Burned     bool   // read destroyed the paste
}

func live(db *gorm.DB) *gorm.DB {
	return db.Where("expiredate = 0 OR expiredate > ?", time.Now().Unix())
}

// peek returns a live paste without consuming it.
func (s *Service) peek(id string) (*model.Paste, error) {
	var p model.Paste
	err := live(s.db).Where("dataid = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &p, err
}

// Read returns a live paste. A burn-after-reading paste is destroyed in the
// same call; of concurrent readers exactly one gets it, the rest ErrNotFound.
func (s *Service) Read(id string) (*View, error) {
	p, err := s.peek(id)
	if err != nil {
		return nil, err
	}
	v := &View{ID: id, Created: p.Created()}
	if err := json.Unmarshal([]byte(p.Data), &v.Stored); err != nil {
		return nil, fmt.Errorf("corrupt paste %s: %w", id, err)
	}
	if model.BurnFlag(v.Stored.AData) {
		if _, err := s.Take(id); err != nil {
			return nil, err
		}
		v.Burned = true
	}
	if p.ExpireDate > 0 {
		ttl := max(p.ExpireDate-time.Now().Unix(), 0)
		v.TimeToLive = &ttl
	}
	return v, nil
}

// IsBurn reports whether a live paste is burn-after-reading, without
// consuming it.
func (s *Service) IsBurn(id string) (bool, error) {
	p, err := s.peek(id)
	if err != nil {
		return false, err
	}
	return p.Burn(), nil
}

// Take atomically deletes a paste (and its comments) and returns it. Of
// concurrent callers exactly one gets the row; the rest get ErrNotFound.
func (s *Service) Take(id string) (*model.Paste, error) {
	var out []model.Paste
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := live(tx).Clauses(clause.Returning{}).Where("dataid = ?", id).Delete(&out).Error; err != nil {
			return err
		}
		if len(out) == 0 {
			return nil
		}
		return tx.Where("pasteid = ?", id).Delete(&model.Comment{}).Error
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return &out[0], nil
}

// Delete removes a paste if token matches. PrivateBin's special token
// "burnafterreading" is accepted for burn pastes.
func (s *Service) Delete(id, token string) error {
	if !hmac.Equal([]byte(s.deleteToken(id)), []byte(token)) {
		p, err := s.peek(id)
		if err != nil {
			return err
		}
		if token != "burnafterreading" || !p.Burn() {
			return ErrWrongToken
		}
	}
	_, err := s.Take(id)
	return err
}

// PurgeExpired deletes expired pastes and their comments, returning the count.
func (s *Service) PurgeExpired() (n int64, err error) {
	now := time.Now().Unix()
	expired := s.db.Model(&model.Paste{}).Select("dataid").Where("expiredate != 0 AND expiredate < ?", now)
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("pasteid IN (?)", expired).Delete(&model.Comment{}).Error; err != nil {
			return err
		}
		res := tx.Where("expiredate != 0 AND expiredate < ?", now).Delete(&model.Paste{})
		n = res.RowsAffected
		return res.Error
	})
	return
}
