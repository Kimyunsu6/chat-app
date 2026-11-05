import { DurableObject } from "cloudflare:workers";

// 채팅방 하나를 담당하는 Durable Object
export class ChatRoom extends DurableObject {
	// 새 접속 요청이 오면 WebSocket 연결을 만든다.
	async fetch(request) {
		const url = new URL(request.url);
		const nickname = url.searchParams.get("nickname");

		// WebSocket의 양쪽 끝을 만든다. (client는 브라우저용, server는 채팅방용)
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];

		// 채팅방이 server 쪽 연결을 맡고, 이 연결의 닉네임을 기억해 둔다.
		this.ctx.acceptWebSocket(server);
		server.serializeAttachment({ nickname: nickname });

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
		const data = JSON.stringify({ nickname: info.nickname, text: text });

		// 접속 중인 모두에게 보낸다. (보낸 사람 포함)
		const sockets = this.ctx.getWebSockets();
		for (const socket of sockets) {
			socket.send(data);
		}
	}
}

// 모든 요청이 처음 도착하는 곳
// (index.html 같은 파일 요청은 public 폴더에서 바로 처리되어 여기로 오지 않는다.)
export default {
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.pathname !== "/ws") {
			return new Response("Not found", { status: 404 });
		}

		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("WebSocket 연결이 필요해요.", { status: 426 });
		}

		let nickname = url.searchParams.get("nickname");
		if (nickname === null) {
			nickname = "";
		}
		nickname = nickname.trim();

		if (nickname === "" || nickname.length > 20) {
			return new Response("닉네임은 1~20자로 입력해 주세요.", { status: 400 });
		}

		// 1단계는 방이 하나뿐이라 모두 "main" 방으로 보낸다.
		const room = env.CHAT_ROOM.getByName("main");
		return room.fetch(request);
	},
};
