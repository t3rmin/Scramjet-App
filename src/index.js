import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// Wisp Configuration: Refer to the documentation at https://npmjs.com

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
	allow_udp_streams: false,
	hostname_blacklist: [/example\.com/],
	dns_servers: ["1.1.1.3", "1.0.0.3"],
});

const fastify = Fastify({
	serverFactory: (handler) => {
		return createServer()
			.on("request", (req, res) => {
				res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
				res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
				handler(req, res);
			})
			.on("upgrade", (req, socket, head) => {
				if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
				else socket.end();
			});
	},
});

// ====================================================
// GLOBAL PASSWORD PROTECTION MIDDLEWARE
// ====================================================
fastify.addHook("onRequest", async (request, reply) => {
	const expectedPassword = process.env.PROXY_PASSWORD;
	
	// If no password environment variable is set on Render, bypass security
	if (!expectedPassword) return;

	// 1. Check if they have a valid authorization cookie
	const cookieHeader = request.headers.cookie || "";
	if (cookieHeader.includes(`proxy_auth=${expectedPassword}`)) {
		return;
	}

	// 2. Check if they appended ?pass=YOURPASSWORD to the URL
	if (request.query && request.query.pass === expectedPassword) {
		reply.header("Set-Cookie", `proxy_auth=${expectedPassword}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`);
		return reply.redirect("/");
	}

	// 3. Block unauthorized traffic with a clean message
	return reply.code(401).type("text/html").send(`
		<style>
			body { background: #111; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
			.box { border: 1px solid #333; padding: 30px; border-radius: 8px; text-align: center; max-width: 500px; line-height: 1.5; }
			code { background: #222; padding: 4px 8px; border-radius: 4px; color: #ff8c00; font-size: 14px; display: block; margin-top: 10px; word-break: break-all; }
		</style>
		<div class="box">
			<h2>Access Denied</h2>
			<p>This proxy is private. To unlock access for your browser, append your secret password to the end of your URL like this:</p>
			<code>https://${request.headers.host || "your-site"}/?pass=YOUR_PASSWORD</code>
		</div>
	`);
});
// ====================================================

fastify.register(fastifyStatic, {
	root: publicPath,
	decorateReply: true,
});

fastify.register(fastifyStatic, {
	root: scramjetPath,
	prefix: "/scram/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: libcurlPath,
	prefix: "/libcurl/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: baremuxPath,
	prefix: "/baremux/",
	decorateReply: false,
});

fastify.setNotFoundHandler((res, reply) => {
	return reply.code(404).type("text/html").sendFile("404.html");
});

fastify.server.on("listening", () => {
	const address = fastify.server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	fastify.close();
	process.exit(0);
}

let port = parseInt(process.env.PORT || "");

if (isNaN(port)) port = 8080;

fastify.listen({
	port: port,
	host: "0.0.0.0",
});
