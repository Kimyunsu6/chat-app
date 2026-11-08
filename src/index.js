import { DurableObject } from "cloudflare:workers";

// 채팅방 하나를 담당하는 Durable Object
// 방 이름마다 하나씩 따로 만들어지고, 저장 공간(SQLite)도 방마다 따로 있다.
export class ChatRoom extends DurableObject {
	constructor(ctx, env) {
		super(ctx, env);

		// 메시지를 저장할 표를 만든다. (이미 있으면 그냥 넘어간다.)
		this.ctx.storage.sql.exec(
			"CREATE TABLE IF NOT EXISTS messages (" +
				"id INTEGER PRIMARY KEY AUTOINCREMENT, " +
				"nickname TEXT, " +
				"text TEXT, " +
				"created_at INTEGER" +
				")"
		);
	}

	// 새 접속 요청이 오면 WebSocket 연결을 만든다.
	// username은 Worker가 로그인을 확인한 뒤 넣어 준 값이라서 믿을 수 있다.
	async fetch(request) {
		const url = new URL(request.url);
		const username = url.searchParams.get("username");

		// WebSocket의 양쪽 끝을 만든다. (client는 브라우저용, server는 채팅방용)
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];

		// 채팅방이 server 쪽 연결을 맡고, 이 연결의 이름을 기억해 둔다.
		this.ctx.acceptWebSocket(server);
		server.serializeAttachment({ nickname: username });

		// 최근 메시지 50개를 꺼낸다. (최신 것부터 50개)
		const rows = this.ctx.storage.sql
			.exec("SELECT nickname, text FROM messages ORDER BY id DESC LIMIT 50")
			.toArray();

		// 오래된 것부터 보이도록 순서를 뒤집어서, 방금 들어온 사람에게만 보낸다.
		rows.reverse();
		for (const row of rows) {
			server.send(JSON.stringify({ nickname: row.nickname, text: row.text }));
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	// 누군가 메시지를 보내면 실행된다.
	async webSocketMessage(ws, message) {
		// 글자가 아닌 데이터는 무시한다.
		if (typeof message !== "string") {
			return;
		}

		const text = message.trim();
		if (text === "" || text.length > 1000) {
			return;
		}

		// 보낸 사람의 이름을 붙인다.
		const info = ws.deserializeAttachment();

		// 먼저 저장한다. (? 자리에 값이 안전하게 들어간다.)
		this.ctx.storage.sql.exec(
			"INSERT INTO messages (nickname, text, created_at) VALUES (?, ?, ?)",
			info.nickname,
			text,
			Date.now()
		);

		const data = JSON.stringify({ nickname: info.nickname, text: text });

		// 접속 중인 모두에게 보낸다. (보낸 사람 포함)
		const sockets = this.ctx.getWebSockets();
		for (const socket of sockets) {
			socket.send(data);
		}
	}
}

// ---------- 작은 도우미 함수들 ----------

// 1~20자인지 확인한다. (앞뒤 공백은 지우고 확인)
function cleanName(value) {
	if (value === null) {
		return "";
	}
	value = value.trim();
	if (value.length > 20) {
		return "";
	}
	return value;
}

// 결과를 JSON으로 돌려준다. cookie가 있으면 쿠키도 같이 보낸다.
function jsonResponse(data, status, cookie) {
	const headers = new Headers();
	headers.set("Content-Type", "application/json; charset=utf-8");
	if (cookie) {
		headers.set("Set-Cookie", cookie);
	}
	return new Response(JSON.stringify(data), { status: status, headers: headers });
}

// 요청에 담긴 쿠키 중에서 name에 해당하는 값을 찾는다.
// 쿠키는 "a=1; session=abc" 처럼 한 줄로 온다.
function getCookie(request, name) {
	const header = request.headers.get("Cookie");
	if (header === null) {
		return "";
	}
	const parts = header.split(";");
	for (const part of parts) {
		const pair = part.trim().split("=");
		if (pair[0] === name) {
			return pair[1];
		}
	}
	return "";
}

// 숫자 배열(바이트)을 "3fa9..." 같은 16진수 글자로 바꾼다.
function toHex(bytes) {
	let result = "";
	for (const b of bytes) {
		result = result + b.toString(16).padStart(2, "0");
	}
	return result;
}

// 비밀번호를 해시로 바꾼다. (PBKDF2 + SHA-256, 10만 번 반복)
// 같은 비밀번호라도 salt가 다르면 완전히 다른 해시가 나온다.
async function hashPassword(password, salt) {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			hash: "SHA-256",
			salt: encoder.encode(salt),
			iterations: 100000,
		},
		key,
		256
	);
	return toHex(new Uint8Array(bits));
}

// 두 해시가 같은지 비교한다.
// timingSafeEqual은 비교하는 데 걸리는 시간이 항상 같아서, 시간을 재서 맞히는 공격을 막는다.
function sameHash(a, b) {
	const encoder = new TextEncoder();
	const x = encoder.encode(a);
	const y = encoder.encode(b);
	if (x.length !== y.length) {
		return false;
	}
	return crypto.subtle.timingSafeEqual(x, y);
}

// 요청 본문(JSON)을 읽는다. 이상한 값이면 null을 돌려준다.
async function readJson(request) {
	try {
		return await request.json();
	} catch (error) {
		return null;
	}
}

const SESSION_DAYS = 7;

// 로그인 토큰을 새로 만들어 D1에 저장하고, 브라우저에 보낼 쿠키 글자를 돌려준다.
async function createSession(env, userId, url) {
	const token = crypto.randomUUID();
	const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;

	await env.DB.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
		.bind(token, userId, expiresAt)
		.run();

	return makeCookie(token, SESSION_DAYS * 24 * 60 * 60, url);
}

// 쿠키 글자를 만든다.
// HttpOnly: 자바스크립트가 쿠키를 못 읽게 한다. (토큰을 훔쳐 가지 못하게)
// SameSite=Lax: 다른 사이트에서 몰래 보낸 요청에는 쿠키가 안 붙는다.
// Secure: https일 때만 쿠키를 보낸다. (로컬 개발은 http라서 그때는 뺀다)
function makeCookie(token, maxAge, url) {
	let cookie = "session=" + token + "; HttpOnly; Path=/; SameSite=Lax; Max-Age=" + maxAge;
	if (url.protocol === "https:") {
		cookie = cookie + "; Secure";
	}
	return cookie;
}

// 쿠키를 보고 로그인한 사람을 찾는다.
// 로그인했으면 { id, username }을, 안 했으면 null을 돌려준다.
async function getLoggedInUser(request, env) {
	const token = getCookie(request, "session");
	if (token === "") {
		return null;
	}

	const row = await env.DB.prepare(
		"SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id " +
			"WHERE sessions.token = ? AND sessions.expires_at > ?"
	)
		.bind(token, Date.now())
		.first();

	return row;
}

// ---------- API ----------

// 회원가입: 아이디 3~20자(영문·숫자·_), 비밀번호 8~100자
async function signup(request, env, url) {
	const body = await readJson(request);
	if (body === null || typeof body.username !== "string" || typeof body.password !== "string") {
		return jsonResponse({ error: "아이디와 비밀번호를 입력해 주세요." }, 400);
	}

	const username = body.username.trim();
	const password = body.password;

	if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
		return jsonResponse({ error: "아이디는 영문·숫자·_ 로 3~20자여야 해요." }, 400);
	}
	if (password.length < 8 || password.length > 100) {
		return jsonResponse({ error: "비밀번호는 8~100자여야 해요." }, 400);
	}

	const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
	if (existing !== null) {
		return jsonResponse({ error: "이미 있는 아이디예요." }, 409);
	}

	// 사람마다 다른 랜덤 salt를 만든다.
	const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
	const passwordHash = await hashPassword(password, salt);

	let result;
	try {
		result = await env.DB.prepare("INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)")
			.bind(username, passwordHash, salt, Date.now())
			.run();
	} catch (error) {
		// 거의 동시에 같은 아이디로 가입하면 여기로 온다. (UNIQUE 규칙)
		return jsonResponse({ error: "이미 있는 아이디예요." }, 409);
	}

	// 가입하면 바로 로그인 상태로 만든다.
	const cookie = await createSession(env, result.meta.last_row_id, url);
	return jsonResponse({ username: username }, 200, cookie);
}

// 로그인
async function login(request, env, url) {
	const body = await readJson(request);
	if (body === null || typeof body.username !== "string" || typeof body.password !== "string") {
		return jsonResponse({ error: "아이디와 비밀번호를 입력해 주세요." }, 400);
	}

	const username = body.username.trim();
	const password = body.password;
	if (password.length > 100) {
		return jsonResponse({ error: "아이디 또는 비밀번호가 틀렸어요." }, 401);
	}

	const user = await env.DB.prepare("SELECT id, password_hash, salt FROM users WHERE username = ?")
		.bind(username)
		.first();

	// 아이디가 없을 때와 비밀번호가 틀릴 때 같은 말을 해서, 어떤 아이디가 있는지 알 수 없게 한다.
	if (user === null) {
		return jsonResponse({ error: "아이디 또는 비밀번호가 틀렸어요." }, 401);
	}

	const passwordHash = await hashPassword(password, user.salt);
	if (!sameHash(passwordHash, user.password_hash)) {
		return jsonResponse({ error: "아이디 또는 비밀번호가 틀렸어요." }, 401);
	}

	// 기간이 지난 토큰은 이참에 지운다.
	await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();

	const cookie = await createSession(env, user.id, url);
	return jsonResponse({ username: username }, 200, cookie);
}

// 로그아웃: D1에서 토큰을 지우고, 쿠키도 바로 만료시킨다.
async function logout(request, env, url) {
	const token = getCookie(request, "session");
	if (token !== "") {
		await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
	}
	return jsonResponse({ ok: true }, 200, makeCookie("", 0, url));
}

// 지금 로그인한 사람이 누구인지 알려준다.
async function me(request, env) {
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return jsonResponse({ error: "로그인이 필요해요." }, 401);
	}
	return jsonResponse({ username: user.username }, 200);
}

// ---------- 친구 ----------

// 두 사람의 번호로 항상 똑같은 글자를 만든다. (3과 7이든 7과 3이든 "3:7")
function makePairKey(a, b) {
	if (a < b) {
		return a + ":" + b;
	}
	return b + ":" + a;
}

// 아이디로 친구 신청을 보낸다.
async function requestFriend(request, env) {
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return jsonResponse({ error: "로그인이 필요해요." }, 401);
	}

	const body = await readJson(request);
	if (body === null || typeof body.username !== "string") {
		return jsonResponse({ error: "친구의 아이디를 입력해 주세요." }, 400);
	}

	const target = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(body.username.trim()).first();
	if (target === null) {
		return jsonResponse({ error: "없는 아이디예요." }, 404);
	}
	if (target.id === user.id) {
		return jsonResponse({ error: "나 자신에게는 신청할 수 없어요." }, 400);
	}

	const pairKey = makePairKey(user.id, target.id);

	// 두 사람 사이에 이미 신청이나 친구 관계가 있는지 확인한다.
	const existing = await env.DB.prepare("SELECT requester_id, status FROM friends WHERE pair_key = ?")
		.bind(pairKey)
		.first();
	if (existing !== null) {
		if (existing.status === "accepted") {
			return jsonResponse({ error: "이미 친구예요." }, 409);
		}
		if (existing.requester_id === user.id) {
			return jsonResponse({ error: "이미 신청했어요." }, 409);
		}
		return jsonResponse({ error: "상대가 먼저 신청했어요. 받은 신청을 수락해 주세요." }, 409);
	}

	try {
		await env.DB.prepare(
			"INSERT INTO friends (requester_id, addressee_id, pair_key, status, created_at) VALUES (?, ?, ?, 'pending', ?)"
		)
			.bind(user.id, target.id, pairKey, Date.now())
			.run();
	} catch (error) {
		// 거의 동시에 서로 신청하면 여기로 온다. (UNIQUE 규칙)
		return jsonResponse({ error: "이미 신청이 있어요. 새로고침해 주세요." }, 409);
	}

	return jsonResponse({ ok: true }, 200);
}

// 받은 친구 신청을 수락한다.
// addressee_id까지 확인하므로 나에게 온 신청만 수락할 수 있다.
async function acceptFriend(request, env) {
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return jsonResponse({ error: "로그인이 필요해요." }, 401);
	}

	const body = await readJson(request);
	if (body === null || typeof body.id !== "number") {
		return jsonResponse({ error: "잘못된 요청이에요." }, 400);
	}

	const result = await env.DB.prepare(
		"UPDATE friends SET status = 'accepted' WHERE id = ? AND addressee_id = ? AND status = 'pending'"
	)
		.bind(body.id, user.id)
		.run();

	if (result.meta.changes === 0) {
		return jsonResponse({ error: "수락할 수 있는 신청이 아니에요." }, 404);
	}
	return jsonResponse({ ok: true }, 200);
}

// 내 친구 목록을 돌려준다.
async function listFriends(request, env) {
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return jsonResponse({ error: "로그인이 필요해요." }, 401);
	}

	// CASE: 내가 신청한 쪽이면 받은 사람이, 내가 받은 쪽이면 신청한 사람이 친구이다.
	const result = await env.DB.prepare(
		"SELECT users.username FROM friends " +
			"JOIN users ON users.id = CASE WHEN friends.requester_id = ? THEN friends.addressee_id ELSE friends.requester_id END " +
			"WHERE friends.status = 'accepted' AND (friends.requester_id = ? OR friends.addressee_id = ?) " +
			"ORDER BY users.username"
	)
		.bind(user.id, user.id, user.id)
		.run();

	return jsonResponse({ friends: result.results }, 200);
}

// 내가 받은 친구 신청 목록을 돌려준다.
async function listFriendRequests(request, env) {
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return jsonResponse({ error: "로그인이 필요해요." }, 401);
	}

	const result = await env.DB.prepare(
		"SELECT friends.id, users.username FROM friends " +
			"JOIN users ON users.id = friends.requester_id " +
			"WHERE friends.addressee_id = ? AND friends.status = 'pending' " +
			"ORDER BY friends.created_at"
	)
		.bind(user.id)
		.run();

	return jsonResponse({ requests: result.results }, 200);
}

// ---------- 채팅방 접속 ----------

async function connectChat(request, env, url) {
	if (request.headers.get("Upgrade") !== "websocket") {
		return new Response("WebSocket 연결이 필요해요.", { status: 426 });
	}

	// 다른 사이트에서 몰래 우리 채팅방에 접속하지 못하게 막는다.
	const origin = request.headers.get("Origin");
	if (origin !== null && origin !== url.origin) {
		return new Response("허용되지 않은 접속이에요.", { status: 403 });
	}

	// 로그인 안 한 사람은 못 들어온다.
	const user = await getLoggedInUser(request, env);
	if (user === null) {
		return new Response("로그인이 필요해요.", { status: 401 });
	}

	const roomName = cleanName(url.searchParams.get("room"));
	if (roomName === "") {
		return new Response("방 이름은 1~20자로 입력해 주세요.", { status: 400 });
	}

	// 채팅방에는 서버가 확인한 아이디만 넘긴다. (브라우저가 보낸 이름은 쓰지 않는다)
	const roomUrl = new URL(url);
	roomUrl.search = "?username=" + encodeURIComponent(user.username);

	// 방 이름이 같으면 같은 채팅방, 다르면 다른 채팅방으로 간다.
	const room = env.CHAT_ROOM.getByName(roomName);
	return room.fetch(new Request(roomUrl, request));
}

// 모든 요청이 처음 도착하는 곳
// (index.html 같은 파일 요청과 /room/... 페이지 열기는 public 폴더에서 바로 처리되어 여기로 오지 않는다.)
export default {
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.pathname === "/ws") {
			return connectChat(request, env, url);
		}

		// 조회하는 API는 GET, 무언가를 바꾸는 API는 POST로만 받는다.
		if (url.pathname === "/api/me" && request.method === "GET") {
			return me(request, env);
		}
		if (url.pathname === "/api/friends" && request.method === "GET") {
			return listFriends(request, env);
		}
		if (url.pathname === "/api/friends/requests" && request.method === "GET") {
			return listFriendRequests(request, env);
		}
		if (url.pathname === "/api/friends/request" && request.method === "POST") {
			return requestFriend(request, env);
		}
		if (url.pathname === "/api/friends/accept" && request.method === "POST") {
			return acceptFriend(request, env);
		}
		if (url.pathname === "/api/signup" && request.method === "POST") {
			return signup(request, env, url);
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			return login(request, env, url);
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return logout(request, env, url);
		}

		return new Response("Not found", { status: 404 });
	},
};
