"""dashboard.py — живой просмотр обучения (локально, без внешних библиотек).

  python ml/dashboard.py --run F:\\AIproject\\ml-runs\\tf_100k --port 8773

Открой http://127.0.0.1:8773/ — графики loss/acc, текущая эпоха, примеры
«что модель думает» и итоговая матрица ошибок. Данные читаются из
<run>.jsonl, который пишет train.py.
"""
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>training</title><style>
  :root{color-scheme:dark} *{box-sizing:border-box}
  body{margin:0;background:#070707;color:#e8e8e8;font:13px/1.6 ui-monospace,Consolas,monospace}
  .wrap{max-width:1000px;margin:0 auto;padding:20px}
  .card{background:#0d0d0d;border:1px solid #1c1c1c;border-radius:12px;padding:16px;margin-bottom:12px}
  h2{font-size:13px;font-weight:500;color:#9a9a9a;margin:0 0 10px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .kpi{flex:1;min-width:120px;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:8px 10px}
  .kpi b{display:block;font-size:18px;color:#fff;font-weight:500}
  .kpi span{font-size:11px;color:#6f6f6f}
  canvas{width:100%;height:170px;display:block}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{text-align:left;padding:3px 6px;border-bottom:1px solid #171717}
  th{color:#6f6f6f;font-weight:400}
  .bar{height:6px;background:#222;border-radius:3px;overflow:hidden;min-width:80px}
  .bar i{display:block;height:100%;background:#7f9f7f}
  .muted{color:#6f6f6f}.good{color:#7fbf7f}.bad{color:#bf7f7f}
</style></head><body><div class="wrap">
<div class="card"><h2>обучение</h2><div class="row" id="kpis"></div></div>
<div class="card"><h2>loss</h2><canvas id="loss"></canvas></div>
<div class="card"><h2>accuracy</h2><canvas id="acc"></canvas></div>
<div class="card"><h2>что модель думает (последняя эпоха)</h2><table id="samples"></table></div>
<div class="card"><h2>итог</h2><div id="final" class="muted">ещё учится…</div></div>
</div><script>
const $ = s => document.querySelector(s);
function draw(id, series){
  const c = $(id), dpr = devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  c.width = w*dpr; c.height = h*dpr;
  const g = c.getContext('2d'); g.scale(dpr,dpr); g.clearRect(0,0,w,h);
  const all = series.flatMap(s=>s.data);
  if(!all.length){ g.fillStyle='#555'; g.fillText('нет данных',10,20); return; }
  const xs = series[0].data.map((_,i)=>i+1);
  const ymin = Math.min(...all), ymax = Math.max(...all);
  const pad = 28, Y = v => h-12-(v-ymin)/(ymax-ymin||1)*(h-pad-12);
  const X = i => 10+i/(Math.max(1,xs.length-1))*(w-20);
  g.strokeStyle='#1a1a1a'; g.beginPath();
  for(let k=0;k<=3;k++){const y=12+k*(h-pad-12)/3; g.moveTo(10,y); g.lineTo(w-10,y);} g.stroke();
  g.fillStyle='#555'; g.font='10px monospace';
  g.fillText(ymax.toFixed(2),2,14); g.fillText(ymin.toFixed(2),2,h-4);
  series.forEach(s=>{
    g.strokeStyle=s.color; g.lineWidth=1.6; g.beginPath();
    s.data.forEach((v,i)=>{ i?g.lineTo(X(i),Y(v)):g.moveTo(X(i),Y(v)); }); g.stroke();
    g.fillStyle=s.color; g.fillText(s.name, w-70, 14+12*series.indexOf(s));
  });
}
async function tick(){
  try{
    const st = await (await fetch('/api/state')).json();
    const ep = st.epochs || [];
    const last = ep[ep.length-1] || {};
    $('#kpis').innerHTML = [
      ['эпоха', last.epoch ?? '—'], ['train loss', last.train_loss ?? '—'],
      ['val loss', last.val_loss ?? '—'], ['val acc', last.val_acc ?? '—'],
      ['top2', last.val_top2 ?? '—'], ['сек', last.sec ?? '—'],
    ].map(([k,v])=>`<div class="kpi"><b>${v}</b><span>${k}</span></div>`).join('');
    draw('#loss', [{name:'train',color:'#7f9f7f',data:ep.map(e=>e.train_loss)},
                   {name:'val',color:'#9f8f6f',data:ep.map(e=>e.val_loss)}]);
    draw('#acc', [{name:'val',color:'#6f9fbf',data:ep.map(e=>e.val_acc)},
                  {name:'top2',color:'#9a7fbf',data:ep.map(e=>e.val_top2)}]);
    const ss = (last.samples||[]);
    $('#samples').innerHTML = '<tr><th>true</th><th>top-3 (вероятности)</th></tr>' +
      ss.map(s=>`<tr><td>${s.true}</td><td>${s.preds.map(p=>
        `<span class="muted">${p.family}</span> <div class="bar" style="display:inline-block;width:90px"><i style="width:${p.p*100}%"></i></div> ${p.p.toFixed(2)}`).join(' &nbsp; ')}</td></tr>`).join('');
    if(st.final){
      const f = st.final;
      const t = f.test || {};
      $('#final').innerHTML = `<span class="good">test acc ${t.acc?.toFixed(3)}</span>, top2 ${t.top2?.toFixed(3)}; ` +
        (f.ood && f.ood.n ? `OOD: mean max prob ${f.ood.mean_max_prob}, ниже 0.5 — ${Math.round(f.ood["share_below_0.5"]*100)}%` : '') +
        (f.confusion ? '<br><span class="muted">матрица ошибок сохранена в metrics.json</span>' : '');
    }
  }catch(e){ $('#final').textContent = 'нет связи с train.py: '+e; }
}
tick(); setInterval(tick, 1500);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ml-dash"

    def log_message(self, *a):
        pass

    def _json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        run = self.server.run_prefix
        if self.path.split("?")[0] == "/api/state":
            epochs, final = [], None
            try:
                with open(run + ".jsonl", encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if ev.get("type") == "epoch":
                            epochs.append(ev)
                        elif ev.get("type") == "final":
                            final = ev
            except OSError:
                pass
            return self._json({"epochs": epochs[-500:], "final": final})
        if self.path.split("?")[0] in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True,
                    help="префикс без .jsonl (как --out в train.py)")
    ap.add_argument("--port", type=int, default=8773)
    args = ap.parse_args()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.run_prefix = os.path.abspath(args.run)
    print(f"[+] http://127.0.0.1:{args.port}/  (run={httpd.run_prefix})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
