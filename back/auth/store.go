package auth

import "database/sql"

// Store provides database-backed operations needed by authorization flows.
type Store struct {
	db *sql.DB
}

// NewStore constructs a Store backed by the given sql.DB.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}
