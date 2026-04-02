CREATE TABLE IF NOT EXISTS user_profiles (
  user_id TEXT PRIMARY KEY,
  display_name TEXT,
  avatar_data_url TEXT,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_updated_at ON user_profiles(updated_at);

INSERT INTO user_profiles (user_id, display_name, avatar_data_url, updated_at)
SELECT
  settings.user_id,
  NULLIF(TRIM(COALESCE(json_extract(settings.payload_json, '$.profile.displayName'), '')), ''),
  NULLIF(TRIM(COALESCE(json_extract(settings.payload_json, '$.profile.avatarDataUrl'), '')), ''),
  COALESCE(
    CAST(json_extract(settings.payload_json, '$.profile.updatedAt') AS INTEGER),
    settings.updated_at
  )
FROM user_settings AS settings
WHERE (
  NULLIF(TRIM(COALESCE(json_extract(settings.payload_json, '$.profile.displayName'), '')), '') IS NOT NULL
  OR NULLIF(TRIM(COALESCE(json_extract(settings.payload_json, '$.profile.avatarDataUrl'), '')), '') IS NOT NULL
)
AND settings.updated_at = (
  SELECT MAX(candidate.updated_at)
  FROM user_settings AS candidate
  WHERE candidate.user_id = settings.user_id
    AND (
      NULLIF(TRIM(COALESCE(json_extract(candidate.payload_json, '$.profile.displayName'), '')), '') IS NOT NULL
      OR NULLIF(TRIM(COALESCE(json_extract(candidate.payload_json, '$.profile.avatarDataUrl'), '')), '') IS NOT NULL
    )
)
ON CONFLICT(user_id) DO UPDATE SET
  display_name = excluded.display_name,
  avatar_data_url = excluded.avatar_data_url,
  updated_at = excluded.updated_at;
