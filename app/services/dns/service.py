import dns.resolver
from app.schemas.dns import DNSRecords
from app.utils.validation import check_ssrf_and_get_ip
from app.core.exceptions import DNSError
from app.utils.logging import logger

class DNSService:
    @staticmethod
    def lookup(domain: str) -> DNSRecords:
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 2.0, 4.0
        results = {x: [] for x in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]}
        for rtype in results:
            try:
                for rdata in resolver.resolve(domain, rtype):
                    if rtype in ("A", "AAAA"): value = rdata.address
                    elif rtype == "MX": value = f"{rdata.preference} {rdata.exchange.to_text().rstrip('.') }"
                    elif rtype in ("NS", "CNAME"): value = rdata.target.to_text().rstrip('.')
                    elif rtype == "TXT": value = b"".join(rdata.strings).decode("utf-8", "replace")
                    else: value = f"mname={rdata.mname.to_text().rstrip('.')} rname={rdata.rname.to_text().rstrip('.')} serial={rdata.serial} refresh={rdata.refresh} retry={rdata.retry} expire={rdata.expire} minimum={rdata.minimum}"
                    results[rtype].append(str(value))
            except dns.resolver.NXDOMAIN as exc: raise DNSError(f"The domain '{domain}' does not exist (NXDOMAIN).") from exc
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout): continue
            except Exception as exc: logger.warning("DNS %s query failed for %s: %s", rtype, domain, exc)
        if all(not values for values in results.values()): raise DNSError(f"Could not resolve any DNS records for domain: {domain}")
        return DNSRecords(**results)
