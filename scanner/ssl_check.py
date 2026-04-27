import ssl, socket
from datetime import datetime

def check_ssl(hostname):
    issues = []
    if not hostname:
        return [{"message":"No hostname","severity":"info"}]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(6); s.connect((hostname,443))
            cert   = s.getpeercert()
            cipher = s.cipher()
            exp    = cert.get("notAfter","")
            if exp:
                dt   = datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z")
                days = (dt - datetime.utcnow()).days
                if   days < 0:   issues.append({"message":"Certificate EXPIRED","severity":"critical"})
                elif days < 30:  issues.append({"message":f"Expires in {days} days","severity":"high"})
                else:            issues.append({"message":f"Valid — {days} days remaining","severity":"ok"})
            if cipher:
                name = cipher[0]
                if any(w in name for w in ("RC4","DES","NULL","EXPORT")):
                    issues.append({"message":f"Weak cipher: {name}","severity":"high"})
                else:
                    issues.append({"message":f"Cipher: {name}","severity":"ok"})
            ver = s.version()
            if ver in ("TLSv1","TLSv1.1","SSLv3","SSLv2"):
                issues.append({"message":f"Outdated TLS: {ver}","severity":"high"})
            else:
                issues.append({"message":f"TLS: {ver}","severity":"ok"})
    except ssl.SSLCertVerificationError as e:
        issues.append({"message":f"Cert verification failed: {str(e)[:70]}","severity":"critical"})
    except ssl.SSLError as e:
        issues.append({"message":f"SSL error: {str(e)[:70]}","severity":"high"})
    except ConnectionRefusedError:
        issues.append({"message":"Port 443 closed — no HTTPS","severity":"medium"})
    except (socket.timeout, TimeoutError):
        issues.append({"message":"SSL check timed out","severity":"info"})
    except Exception as e:
        issues.append({"message":f"SSL check error: {str(e)[:70]}","severity":"info"})
    return issues
