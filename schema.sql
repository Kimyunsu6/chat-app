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

-- 친구 표
-- status는 'pending'(수락 대기) 또는 'accepted'(친구)이다.
-- pair_key는 두 사람의 번호를 작은 번호부터 쓴 글자이다. (예: 3과 7이면 "3:7")
-- UNIQUE라서 두 사람 사이에는 신청이 하나만 있을 수 있다.
CREATE TABLE IF NOT EXISTS friends (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	requester_id INTEGER NOT NULL,
	addressee_id INTEGER NOT NULL,
	pair_key TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
