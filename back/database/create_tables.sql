USE sa_auth;

CREATE TABLE IF NOT EXISTS session (
  id CHAR(36) NOT NULL,
  session_token CHAR(36) NOT NULL,
  next_security_tool ENUM('LOGIN_FORM') DEFAULT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY idx_session_token (session_token),
  KEY idx_session_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user (
  id CHAR(36) NOT NULL,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY idx_user_username (username),
  UNIQUE KEY idx_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS session_user (
  session_id CHAR(36) NOT NULL,
  user_id CHAR(36) NOT NULL,
  authenticated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id),
  KEY idx_session_user_user_id (user_id),
  CONSTRAINT fk_session_user_session FOREIGN KEY (session_id) REFERENCES session (id) ON DELETE CASCADE,
  CONSTRAINT fk_session_user_user FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS client (
  id CHAR(36) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  client_secret VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  redirect_uri VARCHAR(2048) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY idx_client_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_token (
  id CHAR(36) NOT NULL,
  token VARCHAR(255) NOT NULL,
  session_id CHAR(36) NOT NULL,
  client_id CHAR(36) NOT NULL,
  user_id CHAR(36) NOT NULL,
  scope VARCHAR(1024),
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY idx_access_token_token (token),
  KEY idx_access_token_session (session_id),
  KEY idx_access_token_user (user_id),
  CONSTRAINT fk_access_token_session FOREIGN KEY (session_id) REFERENCES session (id) ON DELETE CASCADE,
  CONSTRAINT fk_access_token_client FOREIGN KEY (client_id) REFERENCES client (id) ON DELETE CASCADE,
  CONSTRAINT fk_access_token_user FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS refresh_token (
  id CHAR(36) NOT NULL,
  token VARCHAR(255) NOT NULL,
  session_id CHAR(36) NOT NULL,
  client_id CHAR(36) NOT NULL,
  user_id CHAR(36) NOT NULL,
  scope VARCHAR(1024),
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY idx_refresh_token_token (token),
  KEY idx_refresh_token_session (session_id),
  KEY idx_refresh_token_user (user_id),
  CONSTRAINT fk_refresh_token_session FOREIGN KEY (session_id) REFERENCES session (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_token_client FOREIGN KEY (client_id) REFERENCES client (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS code_grant (
  session_id CHAR(36) NOT NULL,
  client_id CHAR(36) NOT NULL,
  code VARCHAR(255),
  state VARCHAR(255),
  scope VARCHAR(1024),
  redirect_uri VARCHAR(2048) NOT NULL,
  next_security_tool ENUM('LOGIN_FORM') DEFAULT 'LOGIN_FORM',
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id),
  UNIQUE KEY idx_code_grant_code (code),
  KEY idx_code_grant_session (session_id),
  CONSTRAINT fk_code_grant_session FOREIGN KEY (session_id) REFERENCES session (id) ON DELETE CASCADE,
  CONSTRAINT fk_code_grant_client FOREIGN KEY (client_id) REFERENCES client (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
