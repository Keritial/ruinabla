ALTER TABLE krtl_login_attempts ADD COLUMN mode TEXT NOT NULL DEFAULT 'login';
ALTER TABLE krtl_login_attempts ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_krtl_login_attempts_user_id ON krtl_login_attempts(user_id);
