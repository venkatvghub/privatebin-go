package paste

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkatvghub/privatebin-go/internal/testdb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func testService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(postgres.Open(testdb.DSN(t)), &gorm.Config{NamingStrategy: NamingStrategy("")})
	if err != nil {
		t.Fatal(err)
	}
	s := New(db, "0123456789abcdef0123456789abcdef")
	if err := s.Migrate(""); err != nil {
		t.Fatal(err)
	}
	return s
}

const burnData = `{"v":2,"adata":[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,1],"ct":"AAAA"}`

func TestTakeIsAtomic(t *testing.T) {
	s := testService(t)
	id, _, err := s.insert(burnData, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Take(id); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("want exactly 1 winner, got %d", wins.Load())
	}
}

func TestDeleteTokenAndExpiry(t *testing.T) {
	s := testService(t)
	id, tok, _ := s.insert(burnData, time.Hour)
	if err := s.Delete(id, "nope"); !errors.Is(err, ErrWrongToken) {
		t.Fatalf("want ErrWrongToken, got %v", err)
	}
	if err := s.Delete(id, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.peek(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	id, _, _ = s.insert(burnData, time.Hour)
	if err := s.db.Exec(`UPDATE paste SET expiredate = 1 WHERE dataid = ?`, id).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.peek(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired paste must not be readable")
	}
	if n, err := s.PurgeExpired(); err != nil || n < 1 {
		t.Fatalf("purge: n=%d err=%v", n, err)
	}
}

// Migrate runs at every start. While a request holds a row lock (a burn read
// does), it must neither block nor deadlock against it.
func TestMigrateDoesNotLockExistingTables(t *testing.T) {
	s := testService(t)
	tx := s.db.Begin()
	defer tx.Rollback()
	if err := tx.Exec(`LOCK TABLE paste IN ROW EXCLUSIVE MODE`).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := New(s.db.WithContext(ctx), "0123456789abcdef0123456789abcdef").Migrate(""); err != nil {
		t.Fatalf("Migrate blocked on a held row lock: %v", err)
	}
}
