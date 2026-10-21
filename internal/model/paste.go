// Package model mirrors the PrivateBin 2.1.0 SQL schema so a database can be
// shared with (or migrated from) a PrivateBin instance.
package model

import "encoding/json"

// Paste is table "paste". Tables are created by paste.Service.Migrate (not
// AutoMigrate) and named by the gorm naming strategy, so TABLE_PREFIX applies.
// Data is the JSON {v, adata, ct}; the burn flag is adata[3]. ExpireDate is a
// unix time, 0 meaning never. Meta is JSON with the creation time.
type Paste struct {
	DataID     string `gorm:"column:dataid;primaryKey"`
	Data       string `gorm:"column:data"`
	ExpireDate int64  `gorm:"column:expiredate"`
	Meta       string `gorm:"column:meta"`
}

// ParseFlag reads a PrivateBin boolean flag, sent as a JSON bool or 0/1.
func ParseFlag(raw json.RawMessage) (val, ok bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var n int
	if json.Unmarshal(raw, &n) == nil && (n == 0 || n == 1) {
		return n == 1, true
	}
	return false, false
}

// BurnFlag extracts the burn-after-reading flag, adata[3], from raw adata.
func BurnFlag(adata json.RawMessage) bool {
	var ad []json.RawMessage
	if json.Unmarshal(adata, &ad) != nil || len(ad) != 4 {
		return false
	}
	burn, _ := ParseFlag(ad[3])
	return burn
}

// Burn reports whether the paste is burn-after-reading.
func (p Paste) Burn() bool {
	var d struct {
		AData json.RawMessage `json:"adata"`
	}
	_ = json.Unmarshal([]byte(p.Data), &d)
	return BurnFlag(d.AData)
}

// Created returns the creation unix time from Meta, 0 if unknown.
func (p Paste) Created() int64 {
	var m struct {
		Created int64 `json:"created"`
	}
	_ = json.Unmarshal([]byte(p.Meta), &m)
	return m.Created
}

// Comment is table "comment", reduced to the columns we touch. Discussions are
// not served, but comments are cleaned up so a shared database stays consistent.
type Comment struct {
	DataID  string `gorm:"column:dataid;primaryKey"`
	PasteID string `gorm:"column:pasteid"`
}
