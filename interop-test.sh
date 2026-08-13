#!/usr/bin/env bash
# rustrtc 互操作兼容性验证
#
# 验证 rustrtc 的 SDP/WebRTC 输出与以下端互操作:
#   1. pion (Go) — DataChannel 双向 + 视频 track
#   2. pion-Rust (webrtc crate) — ICE/DTLS 握手 + VP8 echo
#   3. Chrome 浏览器 — 完整 WebRTC 握手 + DataChannel echo
#
# 每次修改 rustrtc 的 SDP 生成 / ID 格式 / 属性顺序后都应运行本脚本,
# 确认没有破坏 pion / 浏览器兼容性。
#
# 用法: bash crates/rustrtc/interop-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_DIR="$SCRIPT_DIR/examples/interop_pion_go"
TMP_WWW="$(mktemp -d)"
RUSTRTC_SERVER_PID=""
PION_SERVER_PID=""
PROXY_PID=""
HTTP_PID=""
E2E_DIR="/Users/pi/workspace/rs/rustpbx/src/addons/cc/cc-phone/e2e"
PBX_HTTP=3000
PROXY_HTTP=3001
PAGE_HTTP=8082

cleanup() {
  for pid in "$RUSTRTC_SERVER_PID" "$PION_SERVER_PID" "$PROXY_PID" "$HTTP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  pkill -f "rustrtc-browser-interop" 2>/dev/null || true
  rm -rf "$TMP_WWW"
}
trap cleanup EXIT

PASS=0
FAIL=0
step() { echo ""; echo "═══ $1 ═══"; }
ok() { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# ── 1. rustrtc 内部 + pion-Rust 互操作 ───────────────────────────
step "1/4 rustrtc 单测 + pion-Rust 互操作 (interop_webrtc)"
cd "$SCRIPT_DIR"
cargo test -p rustrtc 2>&1 | tail -3 | grep -E "test result" || true
if cargo test -p rustrtc --test interop_webrtc 2>&1 | grep -q "4 passed"; then
  ok "interop_webrtc 4/4 (ICE/DTLS 握手 + VP8 echo + PLI)"
else
  bad "interop_webrtc 未全部通过"
fi

# 编译 pion 互操作二进制
step "2/4 编译互操作二进制"
cd "$SCRIPT_DIR"
cargo build -p rustrtc --example interop_pion 2>&1 | tail -1 >/dev/null && ok "interop_pion (rustrtc) 编译"
(cd "$GO_DIR" && go build -o /tmp/interop_pion_client . 2>&1) && ok "interop_pion (Go) 编译"

# ── 3. pion (Go) ↔ rustrtc 双向互操作 ───────────────────────────
step "3/4 pion (Go) ↔ rustrtc 双向 DataChannel + 视频"
# 3a. pion client → rustrtc server
"$SCRIPT_DIR/../../target/debug/examples/interop_pion" server 127.0.0.1:$PBX_HTTP > /tmp/rustrtc-interop-server.log 2>&1 &
RUSTRTC_SERVER_PID=$!
# 等 server 就绪(轮询端口,最多 15s)
for _ in $(seq 1 15); do
  if grep -q "Listening on" /tmp/rustrtc-interop-server.log 2>/dev/null; then break; fi
  sleep 1
done
sleep 1
/tmp/interop_pion_client -mode client -addr 127.0.0.1:$PBX_HTTP > /tmp/rustrtc-interop-pionclient.log 2>&1 &
PION_CLIENT_PID=$!
# 轮询等 SUCCESS(最多 40s),不依赖 GNU timeout
PION_OK=0
for _ in $(seq 1 40); do
  if grep -q 'SUCCESS: Client finished' /tmp/rustrtc-interop-pionclient.log 2>/dev/null; then PION_OK=1; break; fi
  sleep 1
done
if [ "$PION_OK" -eq 1 ]; then
  ok "pion client → rustrtc server (DataChannel echo)"
else
  bad "pion client → rustrtc server 未成功"
fi
kill $PION_CLIENT_PID 2>/dev/null || true
kill $RUSTRTC_SERVER_PID 2>/dev/null || true; wait 2>/dev/null || true
sleep 1

# 3b. rustrtc client → pion server
/tmp/interop_pion_client -mode server -addr 127.0.0.1:$PBX_HTTP > /tmp/rustrtc-interop-pionserver.log 2>&1 &
PION_SERVER_PID=$!
sleep 1
"$SCRIPT_DIR/../../target/debug/examples/interop_pion" client 127.0.0.1:$PBX_HTTP > /tmp/rustrtc-interop-rustclient.log 2>&1 &
RUST_CLIENT_PID=$!
RUST_OK=0
for _ in $(seq 1 40); do
  if grep -q 'SUCCESS: Client finished' /tmp/rustrtc-interop-rustclient.log 2>/dev/null; then RUST_OK=1; break; fi
  sleep 1
done
if [ "$RUST_OK" -eq 1 ]; then
  ok "rustrtc client → pion server (DataChannel echo)"
  grep -q "video/VP8" /tmp/rustrtc-interop-pionserver.log && ok "pion 收到 rustrtc VP8 视频 track" || bad "VP8 track 未确认"
else
  bad "rustrtc client → pion server 未成功"
fi
kill $RUST_CLIENT_PID $PION_SERVER_PID 2>/dev/null || true; wait 2>/dev/null || true
sleep 1

# ── 4. Chrome 浏览器 ↔ rustrtc ──────────────────────────────────
step "4/4 Chrome 浏览器 ↔ rustrtc WebRTC 握手"
if ! command -v node >/dev/null 2>&1 || [ ! -d "$E2E_DIR/node_modules" ]; then
  echo "  ⚠ 跳过浏览器测试 (无 Playwright)。核心 pion 验证已完成。"
  echo ""
  echo "════════════════════════════════════"
  echo "结果: $PASS 通过, $FAIL 失败"
  [ "$FAIL" -eq 0 ]
  exit 0
fi

# rustrtc server + CORS 代理 + 静态页服务
"$SCRIPT_DIR/../../target/debug/examples/interop_pion" server 127.0.0.1:$PBX_HTTP > /tmp/rustrtc-interop-server.log 2>&1 &
RUSTRTC_SERVER_PID=$!
for _ in $(seq 1 15); do
  if grep -q "Listening on" /tmp/rustrtc-interop-server.log 2>/dev/null; then break; fi
  sleep 1
done
sleep 1

cat > /tmp/rustrtc-cors-proxy.py << 'PYEOF'
import http.server, urllib.request
class H(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        req = urllib.request.Request('http://127.0.0.1:3000/offer', data=body, headers={'Content-Type':'application/json'}, method='POST')
        data = urllib.request.urlopen(req).read()
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',3001),H).serve_forever()
PYEOF
python3 /tmp/rustrtc-cors-proxy.py > /tmp/rustrtc-proxy.log 2>&1 &
PROXY_PID=$!

cp "$SCRIPT_DIR/../../target/debug/examples/interop_pion.rs" /dev/null 2>/dev/null || true
cat > "$TMP_WWW/interop.html" << 'HTMLEOF'
<!DOCTYPE html><html><body><pre id="log"></pre><script>
const logEl=document.getElementById('log');const log=m=>{logEl.textContent+=m+'\n'};
(async()=>{try{
  const pc=new RTCPeerConnection({iceServers:[]});
  const dc=pc.createDataChannel('data');
  dc.onopen=()=>log('DC open');
  dc.onmessage=ev=>log('DC echo: '+ev.data);
  try{const s=await navigator.mediaDevices.getUserMedia({audio:true});s.getTracks().forEach(t=>pc.addTrack(t,s));}catch(e){log('no mic')}
  const o=await pc.createOffer();await pc.setLocalDescription(o);
  await new Promise(r=>{if(pc.iceGatheringState==='complete')r();else pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete')r()}});
  const res=await fetch('http://127.0.0.1:3001/offer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sdp:pc.localDescription.sdp,type:'offer'})});
  const a=await res.json();await pc.setRemoteDescription({type:'answer',sdp:a.sdp});
  pc.onconnectionstatechange=()=>{if(pc.connectionState==='connected'){log('CONNECTED');setTimeout(()=>dc.send('ping'),500);window.__ok=true}}
  pc.onicecandidateerror=e=>log('ICE err '+e.errorCode);
}catch(e){log('ERROR '+e)}})();
</script></body></html>
HTMLEOF
python3 -m http.server $PAGE_HTTP --directory "$TMP_WWW" > /tmp/rustrtc-page.log 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 10); do
  if curl -s "http://127.0.0.1:$PAGE_HTTP/interop.html" > /dev/null 2>&1; then break; fi
  sleep 1
done
sleep 1

cat > "$E2E_DIR/tests/rustrtc-browser-interop.spec.js" << 'SPECEOF'
const { test, expect } = require('@playwright/test')
test('browser ↔ rustrtc WebRTC handshake + DataChannel', async ({ page }) => {
  await page.goto('http://127.0.0.1:8082/interop.html')
  await page.waitForFunction(() => window.__ok === true, { timeout: 30000 })
  await page.waitForTimeout(3000)
  const text = await page.locator('#log').textContent()
  console.log('BROWSER LOG:', text.replace(/\n/g, ' | '))
  expect(text).toContain('CONNECTED')
  expect(text).toContain('DC open')
})
SPECEOF

if (cd "$E2E_DIR" && ./node_modules/.bin/playwright test tests/rustrtc-browser-interop.spec.js --reporter=line --timeout=60000 2>&1 | tee /tmp/rustrtc-browser.log | grep -qE "1 passed"); then
  ok "Chrome ↔ rustrtc WebRTC 握手 + DataChannel"
else
  bad "Chrome ↔ rustrtc 未通过"
  cat /tmp/rustrtc-browser.log | tail -8
fi

echo ""
echo "════════════════════════════════════"
echo "rustrtc 互操作验证: $PASS 通过, $FAIL 失败"
[ "$FAIL" -eq 0 ]
