# -*- coding: utf-8 -*-
"""
ANTEN BULUCU v1.0
=================
MD (link) antenlerinin (Radwin, InfiNet, Repeatit vb.) IP adresini bulur,
PC'ye otomatik olarak uygun IP'yi tanimlar ve web arayuzunu acar.

Gereksinimler (bir kez kurulur):
  1. Python 3.9+  (kurulumda "Add to PATH" isaretli olsun)
  2. Npcap        https://npcap.com  ("WinPcap API-compatible mode" isaretli kur)
  3. pip install scapy

Calistirma:  Yonetici olarak calistirilmali (sag tik > Yonetici olarak calistir
             veya app kendisi yetki ister).
"""

import ctypes
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------------------------------------------------------------
# Yonetici yetkisi kontrolu (netsh ve paket yakalama icin gerekli)
# ----------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if os.name == "nt" and not is_admin():
    # Kendini yonetici olarak yeniden baslat
    params = " ".join(f'"{a}"' for a in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    sys.exit(0)

# ----------------------------------------------------------------------------
# Scapy importu (Npcap yoksa anlasilir hata ver)
# ----------------------------------------------------------------------------
try:
    from scapy.all import (  # noqa: E402
        ARP, Ether, IP, sniff, srp, conf,
    )
    conf.verb = 0
    try:
        from scapy.arch.windows import get_windows_if_list  # eski/yeni surumler
    except Exception:
        get_windows_if_list = None
except Exception as e:
    root = tk.Tk(); root.withdraw()
    messagebox.showerror(
        "Eksik bilesen",
        "Scapy yuklenemedi.\n\n"
        "1) Npcap kurulu mu? -> https://npcap.com\n"
        "   (Kurulumda 'WinPcap API-compatible mode' isaretle)\n"
        "2) pip install scapy\n\n"
        f"Hata: {e}"
    )
    sys.exit(1)

def list_ifaces():
    """Ag kartlarini listeler; scapy surumunden bagimsiz calisir."""
    if get_windows_if_list:
        try:
            return get_windows_if_list()
        except Exception:
            pass
    out = []
    try:
        for iface in conf.ifaces.values():
            ips = []
            try:
                raw = getattr(iface, "ips", None)
                if isinstance(raw, dict):
                    ips = list(raw.get(4, [])) + list(raw.get(6, []))
                elif raw:
                    ips = list(raw)
            except Exception:
                pass
            out.append({
                "name": iface.name or iface.description or "",
                "description": iface.description or "",
                "mac": (iface.mac or ""),
                "ips": ips,
            })
    except Exception:
        pass
    return out


APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
BLOCKS_FILE = os.path.join(APP_DIR, "ip_bloklari.txt")
OUI_FILE = os.path.join(APP_DIR, "oui_markalar.json")

DEFAULT_BLOCKS = """# Her satira bir blok. Desteklenen formatlar:
# 192.168.1.0/24
# 192.168.1.1-192.168.1.253
# 192.168.1.5            (tek IP)
# '#' ile baslayan satirlar yorumdur.
# Kendi ag bloklarinizi buraya ekleyin.
10.70.71.0/24
10.70.72.0/24
10.70.73.0/24
10.70.74.0/24
10.70.75.0/24
10.70.76.0/24
10.10.100.0/24
10.10.101.0/24

# Marka fabrika (default) yonetim IP'leri - cihaz sifirlanmis/ilk kurulumsa:
# Radwin (2000/5000/6000 serisi)
192.168.0.1
# InfiNet (InfiLINK/InfiMAN 2x2)
10.10.11.55
# Cambium (ePMP/PTP serisi)
169.254.1.1
# Ceragon (FibeAir IP-10/IP-20) - DOGRULA, kesin degil
192.168.1.1
# Repeatit - DOGRULA, kesin degil
192.168.1.1
"""

# Kendi kesfettigin MAC on-eklerini buraya ekleyebilirsin (dosyadan da duzenlenir)
DEFAULT_OUI = {
    "_aciklama": "MAC adresinin ilk 3 ikilisi : Marka. Yeni cihaz bulunca buraya ekle.",
    "24:A4:3C": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "4C:5E:0C": "MikroTik",
    "64:D1:54": "MikroTik",
    "E4:8D:8C": "MikroTik",
}


def load_blocks_text():
    if not os.path.exists(BLOCKS_FILE):
        with open(BLOCKS_FILE, "w", encoding="utf-8") as f:
            f.write(DEFAULT_BLOCKS)
    with open(BLOCKS_FILE, "r", encoding="utf-8") as f:
        return f.read()


def save_blocks_text(text):
    with open(BLOCKS_FILE, "w", encoding="utf-8") as f:
        f.write(text)


def load_oui():
    if not os.path.exists(OUI_FILE):
        with open(OUI_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_OUI, f, indent=2, ensure_ascii=False)
    try:
        with open(OUI_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k.upper(): v for k, v in data.items() if not k.startswith("_")}
    except Exception:
        return {}


def parse_blocks(text):
    """Blok metnini IP listesine cevirir."""
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                ips.extend(str(h) for h in net.hosts())
            elif "-" in line:
                a, b = [p.strip() for p in line.split("-", 1)]
                start = ipaddress.ip_address(a)
                # "10.70.71.1-253" kisa formatini da destekle
                if "." not in b:
                    b = ".".join(a.split(".")[:3] + [b])
                end = ipaddress.ip_address(b)
                cur = int(start)
                while cur <= int(end):
                    ips.append(str(ipaddress.ip_address(cur)))
                    cur += 1
            else:
                ips.append(str(ipaddress.ip_address(line)))
        except ValueError:
            pass  # bozuk satiri atla
    # sirayi koruyarak tekillestir
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def vendor_of(mac, custom_oui):
    mac = mac.upper()
    pfx = mac[:8]
    if pfx in custom_oui:
        return custom_oui[pfx]
    try:
        if conf.manufdb:
            v = conf.manufdb._get_manuf(mac)
            if v and v != mac:
                return v
    except Exception:
        pass
    return "?"


# ----------------------------------------------------------------------------
# Ana uygulama
# ----------------------------------------------------------------------------
class AntenBulucu(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Anten Bulucu - ISU SCADA")
        self.geometry("860x640")
        self.minsize(760, 560)

        self.msg_q = queue.Queue()
        self.stop_flag = threading.Event()
        self.worker = None
        self.found = {}            # ip -> (mac, vendor, kaynak)
        self.added_ips = []        # [(iface_adi, ip)]
        self.custom_oui = load_oui()

        self._build_ui()
        self._refresh_ifaces()
        self.after(150, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        top = ttk.Frame(self); top.pack(fill="x", **pad)
        ttk.Label(top, text="Ag karti:").pack(side="left")
        self.iface_cb = ttk.Combobox(top, state="readonly", width=52)
        self.iface_cb.pack(side="left", padx=6)
        ttk.Button(top, text="Yenile", command=self._refresh_ifaces).pack(side="left")

        btns = ttk.Frame(self); btns.pack(fill="x", **pad)
        self.btn_passive = ttk.Button(
            btns, text="1) Pasif Dinle (30 sn)", command=self.start_passive)
        self.btn_passive.pack(side="left", padx=(0, 6))
        self.btn_active = ttk.Button(
            btns, text="2) Aktif ARP Tara", command=self.start_active)
        self.btn_active.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(
            btns, text="Durdur", command=self.stop_all, state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Listeyi Temizle", command=self.clear_results
                   ).pack(side="left")

        # IP bloklari
        blk = ttk.LabelFrame(self, text="Aktif tarama IP bloklari (otomatik kaydedilir)")
        blk.pack(fill="x", **pad)
        self.blocks_txt = tk.Text(blk, height=4, font=("Consolas", 10))
        self.blocks_txt.pack(fill="x", padx=6, pady=6)
        self.blocks_txt.insert("1.0", load_blocks_text())

        # Sonuc tablosu
        res = ttk.LabelFrame(self, text="Bulunan cihazlar (baglanmak icin cift tikla)")
        res.pack(fill="both", expand=True, **pad)
        cols = ("ip", "mac", "vendor", "src")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=10)
        for c, t, w in (("ip", "IP Adresi", 140), ("mac", "MAC", 160),
                        ("vendor", "Marka (OUI)", 180), ("src", "Kaynak", 100)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, side="left", padx=(6, 0), pady=6)
        sb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y", pady=6)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<Double-1>", lambda e: self.connect_selected())

        bot = ttk.Frame(self); bot.pack(fill="x", **pad)
        ttk.Button(bot, text="Secili Cihaza Baglan ve Ac",
                   command=self.connect_selected).pack(side="left")
        self.btn_cleanup = ttk.Button(
            bot, text="Eklenen IP'leri Kaldir (0)",
            command=self.cleanup_ips, state="disabled")
        self.btn_cleanup.pack(side="left", padx=8)

        self.status = tk.StringVar(value="Hazir. Anteni tak, once 'Pasif Dinle' dene.")
        sbar = ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w")
        sbar.pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", side="bottom")

    def _refresh_ifaces(self):
        self.ifaces = []
        try:
            for i in list_ifaces():
                name = i.get("name", "")
                desc = i.get("description", "")
                ips = ", ".join(i.get("ips", [])[:2])
                if not name:
                    continue
                self.ifaces.append(name)
                # gorunen metin
                self.iface_cb["values"] = [
                    f"{n}" for n in self.ifaces
                ]
        except Exception as e:
            messagebox.showerror("Hata", f"Ag kartlari listelenemedi:\n{e}")
            return
        # Ethernet iceren ilk karti sec
        vals = list(self.iface_cb["values"])
        pick = 0
        for idx, v in enumerate(vals):
            if "ethernet" in v.lower():
                pick = idx
                break
        if vals:
            self.iface_cb.current(pick)

    def _iface(self):
        return self.iface_cb.get().strip()

    def _log(self, msg):
        self.msg_q.put(("status", msg))

    # ------------------------------------------------------------ Kuyruk
    def _poll_queue(self):
        try:
            while True:
                kind, data = self.msg_q.get_nowait()
                if kind == "status":
                    self.status.set(data)
                elif kind == "progress":
                    cur, total = data
                    self.progress["maximum"] = total
                    self.progress["value"] = cur
                elif kind == "device":
                    ip, mac, src = data
                    self._add_device(ip, mac, src)
                elif kind == "done":
                    self._set_running(False)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _add_device(self, ip, mac, src):
        mac = mac.upper()
        if ip in self.found:
            return
        vendor = vendor_of(mac, self.custom_oui)
        self.found[ip] = (mac, vendor, src)
        self.tree.insert("", "end", values=(ip, mac, vendor, src))
        self.status.set(f"Cihaz bulundu: {ip}  ({mac} / {vendor})")
        self.bell()

    def clear_results(self):
        self.found.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)

    def _set_running(self, running):
        state = "disabled" if running else "normal"
        self.btn_passive["state"] = state
        self.btn_active["state"] = state
        self.btn_stop["state"] = "normal" if running else "disabled"
        if not running:
            self.progress["value"] = 0

    def stop_all(self):
        self.stop_flag.set()
        self._log("Durduruluyor...")

    # ------------------------------------------------------- Pasif dinleme
    def start_passive(self):
        iface = self._iface()
        if not iface:
            messagebox.showwarning("Ag karti", "Once bir ag karti sec.")
            return
        self.stop_flag.clear()
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._passive_worker, args=(iface, 30), daemon=True)
        self.worker.start()

    def _passive_worker(self, iface, duration):
        self._log(f"Pasif dinleme basladi ({duration} sn) - cihazin konusmasi bekleniyor...")
        my_macs = set()
        try:
            for i in list_ifaces():
                m = i.get("mac", "")
                if m:
                    my_macs.add(m.upper())
        except Exception:
            pass

        t_end = time.time() + duration

        def handle(pkt):
            try:
                if pkt.haslayer(ARP):
                    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
                elif pkt.haslayer(IP) and pkt.haslayer(Ether):
                    ip, mac = pkt[IP].src, pkt[Ether].src
                else:
                    return
                if not ip or ip == "0.0.0.0":
                    return
                if mac.upper() in my_macs:
                    return
                self.msg_q.put(("device", (ip, mac, "pasif")))
            except Exception:
                pass

        def stopper(pkt):
            return self.stop_flag.is_set() or time.time() > t_end

        try:
            # ilerleme cubugunu ayri islet
            def prog():
                total = duration
                while time.time() < t_end and not self.stop_flag.is_set():
                    left = max(0, t_end - time.time())
                    self.msg_q.put(("progress", (total - left, total)))
                    time.sleep(0.5)
            threading.Thread(target=prog, daemon=True).start()

            sniff(iface=iface, prn=handle, store=0,
                  stop_filter=stopper, timeout=duration + 2)
        except Exception as e:
            self._log(f"Dinleme hatasi: {e}")
        else:
            n = len(self.found)
            if n:
                self._log(f"Pasif dinleme bitti. {n} cihaz listede.")
            else:
                self._log("Pasif dinlemede cihaz gorulmedi. 'Aktif ARP Tara' butonunu dene.")
        self.msg_q.put(("done", None))

    # -------------------------------------------------------- Aktif tarama
    def start_active(self):
        iface = self._iface()
        if not iface:
            messagebox.showwarning("Ag karti", "Once bir ag karti sec.")
            return
        text = self.blocks_txt.get("1.0", "end")
        save_blocks_text(text)
        ips = parse_blocks(text)
        if not ips:
            messagebox.showwarning(
                "IP blogu yok",
                "Taranacak IP blogu bulunamadi. Ust kutuya blok ekle,\n"
                "ornek: 10.70.71.0/24")
            return
        self.stop_flag.clear()
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._active_worker, args=(iface, ips), daemon=True)
        self.worker.start()

    def _active_worker(self, iface, ips):
        total = len(ips)
        self._log(f"Aktif ARP taramasi: {total} IP taranacak...")
        chunk = 256
        done = 0
        try:
            for i in range(0, total, chunk):
                if self.stop_flag.is_set():
                    self._log("Tarama durduruldu.")
                    break
                batch = ips[i:i + chunk]
                pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                        for ip in batch]
                ans, _ = srp(pkts, iface=iface, timeout=1.5, verbose=0)
                for _, r in ans:
                    self.msg_q.put(("device", (r[ARP].psrc, r[ARP].hwsrc, "aktif")))
                done += len(batch)
                self.msg_q.put(("progress", (done, total)))
                self._log(f"Taraniyor... {done}/{total}")
            else:
                n = len(self.found)
                self._log(f"Tarama bitti. Toplam {n} cihaz bulundu."
                          if n else "Tarama bitti, cihaz bulunamadi. "
                                   "Kabloyu/PoE'yi kontrol et, pasif dinlemeyi dene.")
        except Exception as e:
            self._log(f"Tarama hatasi: {e}")
        self.msg_q.put(("done", None))

    # ------------------------------------------------------------- Baglan
    def connect_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Secim yok", "Listeden bir cihaz sec.")
            return
        ip = self.tree.item(sel[0], "values")[0]
        iface = self._iface()
        if not iface:
            return

        # Ayni /24 icinde bos bir IP sec (once .250, doluysa geri sar)
        dev = ipaddress.ip_address(ip)
        base = ip.rsplit(".", 1)[0]
        my_ip = None
        for last in (250, 249, 248, 247, 246, 245):
            cand = f"{base}.{last}"
            if cand != ip and cand not in self.found:
                my_ip = cand
                break
        if not my_ip:
            messagebox.showerror("IP secilemedi", "Uygun bos IP bulunamadi.")
            return

        cmd = ["netsh", "interface", "ipv4", "add", "address",
               f"name={iface}", my_ip, "255.255.255.0"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            out = (r.stdout or "") + (r.stderr or "")
            already = "zaten" in out.lower() or "already" in out.lower() or \
                      "nesne zaten" in out.lower()
            if r.returncode != 0 and not already:
                messagebox.showerror(
                    "netsh hatasi",
                    f"IP eklenemedi:\n{out}\n\n"
                    "Uygulama yonetici olarak calisiyor mu?")
                return
            if not already:
                self.added_ips.append((iface, my_ip))
                self.btn_cleanup["state"] = "normal"
                self.btn_cleanup["text"] = f"Eklenen IP'leri Kaldir ({len(self.added_ips)})"
            self._log(f"PC'ye {my_ip}/24 eklendi. Cihaz araligi hazir.")
        except Exception as e:
            messagebox.showerror("Hata", f"netsh calistirilamadi:\n{e}")
            return

        # Windows'un IP'yi oturtmasi icin kisa bekleme, sonra tarayici
        self.after(1200, lambda: webbrowser.open(f"http://{ip}"))
        self._log(f"http://{ip} aciliyor... (https gerekiyorsa adres cubugundan degistir)")

    def cleanup_ips(self):
        errs = []
        for iface, ip in list(self.added_ips):
            cmd = ["netsh", "interface", "ipv4", "delete", "address",
                   f"name={iface}", ip]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    self.added_ips.remove((iface, ip))
                else:
                    errs.append(f"{ip}: {r.stdout or r.stderr}")
            except Exception as e:
                errs.append(f"{ip}: {e}")
        n = len(self.added_ips)
        self.btn_cleanup["text"] = f"Eklenen IP'leri Kaldir ({n})"
        if n == 0:
            self.btn_cleanup["state"] = "disabled"
            self._log("Eklenen tum IP'ler kaldirildi.")
        if errs:
            messagebox.showwarning("Bazilari kaldirilamadi", "\n".join(errs))

    # -------------------------------------------------------------- Kapat
    def _on_close(self):
        if self.added_ips:
            if messagebox.askyesno(
                    "Eklenen IP'ler var",
                    "PC'ye eklenen gecici IP'ler duruyor.\n"
                    "Cikmadan once kaldirilsin mi?"):
                self.cleanup_ips()
        self.stop_flag.set()
        self.destroy()


if __name__ == "__main__":
    app = AntenBulucu()
    app.mainloop()
