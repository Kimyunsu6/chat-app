-- 회원 정보 표
-- 비밀번호는 그대로 저장하지 않고, 해시(password_hash)와 salt만 저장한다.
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	salt TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

-- 로그인 상태 표
-- 로그인하면 랜덤 토큰을 하나 만들어 여기에 저장하고, 같은 토큰을 쿠키로 브라우저에 준다.
CREATE TABLE IF NOT EXISTS sessions (
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
