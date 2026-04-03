ALTER TABLE sessions ADD COLUMN app_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_sessions_app_user_id ON sessions(app_id, user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_app_expires_at ON sessions(app_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_app_refresh_hash ON sessions(app_id, refresh_hash);

ALTER TABLE library_profiles ADD COLUMN app_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_library_profiles_user_app_id ON library_profiles(user_id, app_id);

ALTER TABLE user_settings RENAME TO user_settings_old;

CREATE TABLE user_settings (
  user_id TEXT NOT NULL,
  app_id TEXT NOT NULL DEFAULT 'default',
  payload_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, app_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO user_settings (user_id, app_id, payload_json, updated_at)
SELECT user_id, 'default', payload_json, updated_at
FROM user_settings_old;

DROP TABLE user_settings_old;
