import socket
from app.schemas.whois import WhoisRecord
from app.core.exceptions import ValidationError, NullsecError
from app.utils.validation import check_ssrf_and_get_ip, validate_domain_only
from app.utils.logging import logger

class WhoisService:
    """Service to handle secure domain WHOIS queries via direct TCP socket (port 43)."""

    @staticmethod
    def _query_socket(whois_server: str, domain: str, timeout: float = 3.0) -> str:
        """Helper to send a domain query to a specified WHOIS server over TCP port 43."""
        try:
            # Resolve the WHOIS server domain first to verify no SSRF
            check_ssrf_and_get_ip(whois_server)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((whois_server, 43))
                s.sendall(f"{domain}\r\n".encode("utf-8"))
                
                response = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response.append(data.decode("utf-8", errors="replace"))
                return "".join(response)
        except Exception as e:
            logger.warning(f"Failed WHOIS query on {whois_server} for {domain}: {e}")
            return ""

    @classmethod
    def lookup(cls, domain: str) -> WhoisRecord:
        """Look up registrar information for a validated public domain name."""
        domain = domain.strip().lower()
        
        validate_domain_only(domain)
        
        # Phase 1: Query IANA to determine the authoritative WHOIS server for the TLD
        iana_server = "whois.iana.org"
        raw_iana = cls._query_socket(iana_server, domain)
        
        target_whois_server = None
        if raw_iana:
            for line in raw_iana.splitlines():
                if line.lower().startswith("refer:") or line.lower().startswith("whois:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        target_whois_server = parts[1].strip()
                        break
                        
        # Default fallback server mappings if IANA didn't point us correctly
        if not target_whois_server:
            tld = domain.split(".")[-1]
            if tld == "com" or tld == "net":
                target_whois_server = "whois.verisign-grs.com"
            elif tld == "org":
                target_whois_server = "whois.pir.org"
            elif tld == "info":
                target_whois_server = "whois.afilias.net"
            elif tld == "io":
                target_whois_server = "whois.nic.io"
            elif tld == "edu":
                target_whois_server = "whois.educause.edu"
            else:
                target_whois_server = "whois.nic.google" # Fallback guess

        # Phase 2: Query authoritative server
        raw_whois = cls._query_socket(target_whois_server, domain)
        if not raw_whois:
            # If main authoritative failed, try querying verisign or iana return
            raw_whois = raw_iana or "No WHOIS information could be retrieved from the server."
            
        # Parse fields defensively from raw WHOIS content
        registrar = None
        creation_date = None
        expiration_date = None
        status = None
        name_servers = []
        
        for line in raw_whois.splitlines():
            line_stripped = line.strip()
            line_lower = line_stripped.lower()
            
            # Registrar
            if not registrar and any(x in line_lower for x in ["registrar:", "sponsoring registrar:"]):
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    registrar = parts[1].strip()
            
            # Creation date
            if not creation_date and any(x in line_lower for x in ["creation date:", "created:", "created on:"]):
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    creation_date = parts[1].strip()
                    
            # Expiration date
            if not expiration_date and any(x in line_lower for x in ["registry expiry date:", "expiration date:", "expires:", "expires on:"]):
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    expiration_date = parts[1].strip()
                    
            # Domain status
            if not status and "domain status:" in line_lower:
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    status = parts[1].strip().split()[0]
                    
            # Name servers
            if "name server:" in line_lower or "nserver:" in line_lower:
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    ns_val = parts[1].strip().lower().rstrip(".")
                    if ns_val and ns_val not in name_servers:
                        name_servers.append(ns_val)

        return WhoisRecord(
            domain=domain,
            registrar=registrar or "Unknown Registrar",
            creation_date=creation_date or "Unknown",
            expiration_date=expiration_date or "Unknown",
            name_servers=name_servers[:6], # Return up to 6 NS
            status=status or "Active / Registered",
            raw=raw_whois[:20000]
        )
