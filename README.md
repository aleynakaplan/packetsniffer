from scapy.all import sniff, IP, TCP, UDP, ARP
import datetime
import os

def etik_uyari():
    print("=" * 60)
    print(" 🛑 YASAL UYARI:")
    print(" Bu program yalnızca eğitim ve test amaçlı kullanılmalıdır.")
    print(" İzinsiz ağ dinleme, KVKK ve 5651 sayılı yasa kapsamında suçtur.")
    print("=" * 60)
    print()

def paket_analiz(paket, loglama=False):
    zaman = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"[{zaman}] "

    if IP in paket:
        ip_src = paket[IP].src
        ip_dst = paket[IP].dst
        proto = paket[IP].proto
        log += f"IP Paket - Kaynak: {ip_src}, Hedef: {ip_dst}, Protokol: {proto}"

        if TCP in paket:
            log += f", TCP Port: {paket[TCP].sport} -> {paket[TCP].dport}"
        elif UDP in paket:
            log += f", UDP Port: {paket[UDP].sport} -> {paket[UDP].dport}"

    elif ARP in paket:
        log += f"ARP Paket - {paket[ARP].psrc} -> {paket[ARP].pdst}"
    else:
        log += "Bilinmeyen Protokol"

    print(log)

    if loglama:
        with open("packet_logs.txt", "a") as dosya:
            dosya.write(log + "\n")

def tarama_baslat(loglu=False):
    print("\n🔍 Paket dinleme başlatılıyor... (CTRL+C ile durdurabilirsiniz)\n")
    try:
        sniff(prn=lambda x: paket_analiz(x, loglama=loglu), store=False)
    except KeyboardInterrupt:
        print("\n⛔ Tarama durduruldu.")

def menu():
    while True:
        etik_uyari()
        print(" 🧪 MENU:")
        print(" 1 - Hızlı Tarama Başlat (ekran çıktılı)")
        print(" 2 - Loglu Tarama Başlat (export packet_logs.txt)")
        print(" 3 - Çıkış")
        secim = input("\n Seçiminizi girin (1/2/3): ")

        if secim == "1":
            tarama_baslat(loglu=False)
        elif secim == "2":
            tarama_baslat(loglu=True)
        elif secim == "3":
            print("\n👋 Programdan çıkılıyor, görüşmek üzere!")
            break
        else:
            print("⚠️ Geçersiz seçim. Lütfen 1, 2 ya da 3 giriniz.\n")

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    menu()
