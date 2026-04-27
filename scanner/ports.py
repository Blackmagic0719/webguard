import socket

PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",80:"HTTP",443:"HTTPS",
         3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",
         8443:"HTTPS-Alt",27017:"MongoDB"}
RISKY = {21,23,3306,5432,6379,27017}

def scan_ports(hostname, timeout=1.5):
    out = []
    if not hostname: return out
    for port,svc in PORTS.items():
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((hostname,port)) == 0:
                sev = "high" if port in RISKY else "info"
                out.append({"port":port,"service":svc,"severity":sev,
                    "message":f"Port {port}/{svc} open"+(" — potentially dangerous if public" if sev=="high" else "")})
            s.close()
        except Exception:
            pass
    return out
