import threading
import time
import os
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from scapy.all import sniff, IP
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ————— 1. Uvoz testnih podatkov in inicializacija —————
train_df = pd.read_csv("unsw/UNSW_NB15_training-set.csv")
test_df  = pd.read_csv("unsw/UNSW_NB15_testing-set.csv")
for df in (train_df, test_df):
    df["Total Packets"] = df.spkts + df.dpkts
    df["Avg Length"]    = (df.sbytes + df.dbytes) / df["Total Packets"].replace(0,1)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(train_df[["Total Packets","Avg Length"]], train_df["label"])
preds = model.predict(test_df[["Total Packets","Avg Length"]])
print(f"Test accuracy: {accuracy_score(test_df.label, preds):.2%}")

# ————— 2. Simulacija prometa —————
def simulate_traffic():
    row = test_df.sample(1).iloc[0]
    total = int(row.spkts + row.dpkts)
    avg_len = (row.sbytes + row.dbytes) / total if total else 0
    low, high = max(1,int(avg_len*0.5)), max(1,int(avg_len*1.5))
    lengths = np.random.randint(low, high+1, size=total).tolist()
    return lengths, total, avg_len

# ————— 3. Logiranje in filtriranje —————
log_q = queue.Queue()
log_list = []  # (category, line)

def classify(msg: str):
    if "Model=" in msg:
        return "Model"
    if "Pravilo=" in msg:
        return "Rule"
    return "Info"

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} – {msg}"
    log_list.append((classify(msg), line))
    log_q.put(line)

def flush_log():
    while not log_q.empty():
        line = log_q.get()
        cat = classify(line)
        filt = filter_var.get()
        if filt == "Vsi" or filt == cat:
            log_txt.configure(state="normal")
            log_txt.insert(tk.END, line + "\n")
            log_txt.see(tk.END)
            log_txt.configure(state="disabled")
    root.after(200, flush_log)

def update_log_display(event=None):
    log_txt.configure(state="normal")
    log_txt.delete("1.0", tk.END)
    filt = filter_var.get()
    for cat, line in log_list:
        if filt == "Vsi" or filt == cat:
            log_txt.insert(tk.END, line + "\n")
    log_txt.configure(state="disabled")

def save_log():
    path = filedialog.asksaveasfilename(defaultextension=".txt",
                                        filetypes=[("Besedilo","*.txt")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            for _, line in log_list:
                f.write(line + "\n")
        messagebox.showinfo("Izvoz", f"Dnevnik shranjen: {os.path.basename(path)}")
        log("Dnevnik shranjen na disk.")

def clear_log():
    log_list.clear()
    log_txt.configure(state="normal")
    log_txt.delete("1.0", tk.END)
    log_txt.configure(state="disabled")
    log("Dnevnik izpraznjen.")

# ————— 4. Priprava grafov —————
def init_graphs():
    fig, (a1, a2) = plt.subplots(2,1, figsize=(6,4), dpi=100)
    fig.subplots_adjust(bottom=0.20, hspace=0.6)  # room for labels
    a1.set_title("Število paketov")
    a1.set_ylabel("Paketi")
    a2.set_title("Povprečna dolžina paketov", pad=15)
    a2.set_ylabel("Bajti")
    return fig, a1, a2

fig, ax1, ax2 = init_graphs()
cycles, totals, avgs, timestamps = [], [], [], []

def redraw():
    ax1.clear()
    ax2.clear()

    # prvi graf: število paketov
    ax1.plot(cycles, totals, '-o')
    # drugi graf: povprečna dolžina (oranžna črta)
    ax2.plot(cycles, avgs, '-s', color='orange')

    # **pick up to 5 evenly spaced labels** along the span
    n = len(cycles)
    if n > 0:
        count = min(5, n)
        idxs = np.linspace(0, n-1, count, dtype=int)
        ticks = [cycles[i] for i in idxs]
        labels = [timestamps[i] for i in idxs]
    else:
        ticks, labels = [], []

    ax1.set_xticks(ticks)
    ax1.set_xticklabels(labels, rotation=0, ha='center')
    ax2.set_xticks(ticks)
    ax2.set_xticklabels(labels, rotation=0, ha='center')

    ax1.set_title("Število paketov po ciklih")
    ax2.set_title("Povprečna dolžina paketov po ciklih")
    canvas.draw()

# ————— 5. Logični del skeniranja —————
stop_event = threading.Event()
capture_mode = None   # 'real' or 'sim'
capture_thread = None
INTERVAL = 5

def capture_loop_real():
    cycle = 0
    log(f"Začetek realnega zajema (interval {INTERVAL}s)")
    while not stop_event.is_set() and capture_mode == 'real':
        cycle += 1
        timestamps.append(time.strftime("%H:%M:%S"))
        pkts = []
        sniff(timeout=INTERVAL,
              prn=lambda p: pkts.append(len(p)) if IP in p else None,
              store=False)
        total = len(pkts)
        avg   = sum(pkts)/total if total else 0

        log(f"[{cycle}] REAL → paketi={total}, avg={avg:.1f}B")
        pred = model.predict([[total, avg]])[0]
        ml_lbl = "sumljiv" if pred else "normalen"
        rule_lbl = ("DDoS" if total > 200
                    else "Port scanning" if total > 0 and avg < 100
                    else "Normalno")
        log(f"[{cycle}] Model={ml_lbl}; Pravilo={rule_lbl}")

        cycles.append(cycle)
        totals.append(total)
        avgs.append(avg)
        root.after(0, redraw)
    log("Realni zajem ustavljen.")

def capture_loop_sim():
    cycle = 0
    log(f"Začetek simulacije (interval {INTERVAL}s)")
    while not stop_event.is_set() and capture_mode == 'sim':
        cycle += 1
        timestamps.append(time.strftime("%H:%M:%S"))
        lengths, total, avg = simulate_traffic()
        log(f"[{cycle}] SIM → paketi={total}, avg={avg:.1f}B")
        pred = model.predict([[total, avg]])[0]
        ml_lbl = "sumljiv" if pred else "normalen"
        rule_lbl = ("DDoS" if total > 200
                    else "Port scanning" if total > 0 and avg < 100
                    else "Normalno")
        log(f"[{cycle}] Model={ml_lbl}; Pravilo={rule_lbl}")

        cycles.append(cycle)
        totals.append(total)
        avgs.append(avg)
        root.after(0, redraw)
        time.sleep(INTERVAL)
    log("Simulacija ustavljena.")

# ————— 6. Kontrole —————
def start_real():
    global capture_mode, capture_thread
    stop_event.set()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=INTERVAL+1)
    stop_event.clear()
    capture_mode = 'real'
    cycles.clear(); totals.clear(); avgs.clear(); timestamps.clear()
    ax1.clear(); ax2.clear(); redraw()
    capture_thread = threading.Thread(target=capture_loop_real, daemon=True)
    capture_thread.start()
    log("Zagnan realni zajem.")

def start_sim():
    global capture_mode, capture_thread
    stop_event.set()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=INTERVAL+1)
    stop_event.clear()
    capture_mode = 'sim'
    cycles.clear(); totals.clear(); avgs.clear(); timestamps.clear()
    ax1.clear(); ax2.clear(); redraw()
    capture_thread = threading.Thread(target=capture_loop_sim, daemon=True)
    capture_thread.start()
    log("Zagnana simulacija.")

def stop_capture():
    global capture_mode
    stop_event.set()
    capture_mode = None
    log("Ustavitev zajema/simulacije.")

# ————— 7. Uporabniški vmesnik (GUI) —————
root = tk.Tk()
root.title("Pametni sistem za nadzor omrežnega prometa")
root.geometry("950x750")

style = ttk.Style(root)
style.theme_use('clam')
style.configure('.', background='#2e2e2e', foreground='white')
style.configure('TButton', background='#3e3e3e', foreground='white')
style.configure('TLabel', background='#2e2e2e', foreground='white')
style.configure('TFrame', background='#2e2e2e')

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill='both', expand=True)

ctrl = ttk.Frame(main_frame)
ctrl.pack(fill='x', pady=5)
ttk.Button(ctrl, text="Realni zajem", command=start_real).pack(side='left', padx=5)
ttk.Button(ctrl, text="Simulacija", command=start_sim).pack(side='left', padx=5)
ttk.Button(ctrl, text="Ustavi", command=stop_capture).pack(side='left', padx=5)
ttk.Button(ctrl, text="Shrani dnevnik", command=save_log).pack(side='left', padx=5)
ttk.Button(ctrl, text="Počisti dnevnik", command=clear_log).pack(side='left', padx=5)
ttk.Button(ctrl, text="Izhod", command=root.quit).pack(side='left', padx=5)

filter_frame = ttk.Frame(main_frame)
filter_frame.pack(fill='x', pady=5)
ttk.Label(filter_frame, text="Filtriraj dnevnik:").pack(side='left')
filter_var = tk.StringVar(value="Vsi")
cb = ttk.Combobox(filter_frame, textvariable=filter_var,
                  values=["Vsi","Model","Rule"], state='readonly', width=10)
cb.pack(side='left', padx=5)
cb.bind("<<ComboboxSelected>>", update_log_display)

graph_frame = ttk.Frame(main_frame)
graph_frame.pack(fill='both', expand=True, pady=5)
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill='both', expand=True)

log_txt = scrolledtext.ScrolledText(main_frame, height=12,
                                    state='disabled',
                                    bg='#1e1e1e', fg='#dcdcdc',
                                    font=('Courier',10))
log_txt.pack(fill='both', expand=False, pady=5)

root.after(200, flush_log)
root.mainloop()
