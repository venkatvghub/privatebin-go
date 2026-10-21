package paste

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
func (s *Service) Migrate(prefix string) error { // prefix must already be sanitised (config.Load)
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
	for _, q := range stmts {
		if err := s.db.Exec(q).Error; err != nil {
			return err
		}
	}
	return nil
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

// Create stores a paste (data is the JSON {v, adata, ct}) and returns its id
// and delete token.
func (s *Service) Create(data string, expire time.Duration) (id, deleteToken string, err error) {
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

func live(db *gorm.DB) *gorm.DB {
	return db.Where("expiredate = 0 OR expiredate > ?", time.Now().Unix())
}

// Peek returns a live paste without consuming it.
func (s *Service) Peek(id string) (*model.Paste, error) {
	var p model.Paste
	err := live(s.db).Where("dataid = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &p, err
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
		p, err := s.Peek(id)
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
