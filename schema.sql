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

-- 대화방 표
-- type은 'dm'(1:1) 또는 'group'(단톡)이다.
-- dm_key는 1:1 방에만 쓴다. (예: "3:7") UNIQUE라서 같은 두 사람의 방은 하나뿐이다.
-- name은 단톡방 이름이다. 1:1 방은 빈 글자로 둔다.
-- last_message_at은 방 목록을 최근 순서로 보여 줄 때 쓴다.
CREATE TABLE IF NOT EXISTS conversations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type TEXT NOT NULL,
	dm_key TEXT UNIQUE,
	name TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_message_at INTEGER NOT NULL
);

-- 어떤 방에 누가 들어가 있는지 저장하는 표
CREATE TABLE IF NOT EXISTS conversation_members (
	conversation_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	PRIMARY KEY (conversation_id, user_id)
);

-- "내가 들어가 있는 방"을 빨리 찾기 위한 색인
CREATE INDEX IF NOT EXISTS idx_conversation_members_user ON conversation_members (user_id);
