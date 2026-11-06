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
	async fetch(request) {
		const url = new URL(request.url);
		const nickname = url.searchParams.get("nickname").trim();

		// WebSocket의 양쪽 끝을 만든다. (client는 브라우저용, server는 채팅방용)
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];

		// 채팅방이 server 쪽 연결을 맡고, 이 연결의 닉네임을 기억해 둔다.
		this.ctx.acceptWebSocket(server);
		server.serializeAttachment({ nickname: nickname });

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

		// 보낸 사람의 닉네임을 붙인다.
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

// 모든 요청이 처음 도착하는 곳
// (index.html 같은 파일 요청과 /room/... 페이지 열기는 public 폴더에서 바로 처리되어 여기로 오지 않는다.)
export default {
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.pathname !== "/ws") {
			return new Response("Not found", { status: 404 });
		}

		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("WebSocket 연결이 필요해요.", { status: 426 });
		}

		const nickname = cleanName(url.searchParams.get("nickname"));
		if (nickname === "") {
			return new Response("닉네임은 1~20자로 입력해 주세요.", { status: 400 });
		}

		const roomName = cleanName(url.searchParams.get("room"));
		if (roomName === "") {
			return new Response("방 이름은 1~20자로 입력해 주세요.", { status: 400 });
		}

		// 방 이름이 같으면 같은 채팅방, 다르면 다른 채팅방으로 간다.
		const room = env.CHAT_ROOM.getByName(roomName);
		return room.fetch(request);
	},
};
