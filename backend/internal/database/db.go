package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// InitDB initializes the SQLite database and creates tables
func InitDB(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)

	// Test connection
	if err := DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Create demo user
	if err := createDemoUser(); err != nil {
		return fmt.Errorf("failed to create demo user: %w", err)
	}

	return nil
}

// createTables creates all necessary database tables
func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS analyses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		filename TEXT NOT NULL,
		status TEXT NOT NULL,
		error_msg TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		analysis_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		os_type TEXT,
		os_confidence REAL DEFAULT 0,
		mac_address TEXT,
		FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		analysis_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		label TEXT NOT NULL,
		FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS tcp_connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		analysis_id INTEGER NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER NOT NULL,
		dst_port INTEGER NOT NULL,
		bytes_sent INTEGER DEFAULT 0,
		bytes_received INTEGER DEFAULT 0,
		protocol TEXT DEFAULT 'TCP',
		duration_ms INTEGER DEFAULT 0,
		service TEXT,
		start_time TEXT,
		end_time TEXT,
		FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS other_connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		analysis_id INTEGER NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		bytes_sent INTEGER DEFAULT 0,
		bytes_received INTEGER DEFAULT 0,
		protocol TEXT NOT NULL,
		duration_ms INTEGER DEFAULT 0,
		service TEXT,
		start_time TEXT,
		end_time TEXT,
		FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_analyses_user ON analyses(user_id);
	CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
	CREATE INDEX IF NOT EXISTS idx_assets_analysis ON assets(analysis_id);
	CREATE INDEX IF NOT EXISTS idx_targets_analysis ON targets(analysis_id);
	CREATE INDEX IF NOT EXISTS idx_tcp_analysis ON tcp_connections(analysis_id);
	CREATE INDEX IF NOT EXISTS idx_other_analysis ON other_connections(analysis_id);
	`

	_, err := DB.Exec(schema)
	return err
}

// createDemoUser creates the demo user account
func createDemoUser() error {
	// Check if demo user already exists
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "demo").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // Demo user already exists
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("demo"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert demo user
	_, err = DB.Exec(
		"INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		"demo",
		string(hashedPassword),
		time.Now(),
	)

	return err
}

// CleanupExpiredSessions removes expired sessions
func CleanupExpiredSessions() error {
	_, err := DB.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	return err
}

// Close closes the database connection
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}
