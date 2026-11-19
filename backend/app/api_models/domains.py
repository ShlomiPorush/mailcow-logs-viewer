"""What the Domains calls return (routers/domains.py): mailcow's domains with
their stored DNS checks, and a DNS check of one or every domain."""
from typing import Dict, List, Optional, Union

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"
STATUS = "success (passed), warning (passed, with a recommendation) or error (failed or no record)"
STATUS_UNKNOWN = STATUS + "; unknown when it could not be checked"
MAILCOW = "As mailcow reports it: a number, or a numeric string"


# ---------------------------------------------------------------- SPF

class SpfCheckedIp(Fixed):
    ip: str
    source: str = Field(description="auto-detected (the server's IP), transport, relayhost, configured "
                                    "(a manual entry) or dmarc-history")
    authorized: bool = Field(description="The record authorizes this IP")


class SpfCheck(Fixed):
    """The SPF record at the domain (RFC 7208)."""
    status: str = Field(description=STATUS)
    message: str
    record: Optional[str] = Field(description="Null when there is none; every SPF record joined with '; ' "
                                              "when there are several")
    has_strict_all: bool = Field(description="The record has -all")
    includes_mx: bool = Field(description="The record has an mx mechanism")
    includes: List[str] = Field(description="The domains of its include: mechanisms")
    warnings: List[str] = Field(None, description="Only for several records, a record without all, and a record "
                                                  "with valid syntax")
    dns_lookups: int = Field(None, description="The DNS lookups the record costs, its includes and redirect "
                                               "too; more than 10 is an error. Only for a record with valid syntax")
    checked_ips: List[SpfCheckedIp] = Field(None, description="Each source IP checked against the record. Only "
                                                              "for a record with valid syntax; results stored "
                                                              "before this field existed lack it")


# ---------------------------------------------------------------- DKIM

class DkimCheck(Fixed):
    """The DKIM record mailcow signs with, compared with the published one."""
    status: str = Field(description=STATUS)
    message: str
    selector: Optional[str] = Field(description="mailcow's DKIM selector; null when mailcow has no DKIM key or "
                                                "the check failed")
    dkim_domain: str = Field(None, description="Where the record is looked up: <selector>._domainkey.<domain>. "
                                               "Missing when mailcow has no usable DKIM key or the check failed")
    expected_record: Optional[str] = Field(description="mailcow's DKIM record")
    actual_record: Optional[str] = Field(description="The published record; null when there is none")
    match: bool = Field(description="The key, version, key type and permitted hashes match mailcow's record; "
                                    "tag order and compatible differences do not count")
    warnings: List[str] = Field(description="Problems (starting with 'Error: ') and differences from "
                                            "mailcow's record")
    info: List[str]
    parameters: Dict[str, str] = Field(description="The published record's tags, such as v, k, t and p; "
                                                   "empty without a record")


# ---------------------------------------------------------------- DMARC

class DmarcSettings(Fixed):
    """The tags of the published record; a tag that is not published is missing."""
    policy: str = Field(None, description="The p tag")
    subdomain_policy: str = Field(None, description="The sp tag")
    aggregate_report_uris: List[str] = Field(None, description="The rua tag")
    forensic_report_uris: List[str] = Field(None, description="The ruf tag")
    dkim_alignment: str = Field(None, description="The adkim tag")
    spf_alignment: str = Field(None, description="The aspf tag")
    percentage: Union[int, str] = Field(None, description="The pct tag; the text as published when it is not a number")
    failure_reporting_options: str = Field(None, description="The fo tag")


class DmarcCheck(Fixed):
    """The DMARC record at _dmarc.<domain>."""
    status: str = Field(description=STATUS)
    message: str
    record: Optional[str]
    policy: Optional[str] = Field(description="none, quarantine or reject; unknown when the record has none of "
                                              "them; null without a record")
    is_strong: bool = Field(description="The policy is quarantine or reject")
    warnings: List[str]
    settings: DmarcSettings = Field(None, description="The record's tags; not in a check stored before 2.3.0")


# ---------------------------------------------------------------- DNSSEC

class DnssecCheck(Fixed):
    """Whether the domain is DNSSEC signed and validates."""
    status: str = Field(description=STATUS_UNKNOWN)
    message: str
    record: None = Field(description="Always null")
    validated: Optional[bool] = Field(description="Validating resolvers validated the domain; null when it "
                                                  "could not be checked")
    warnings: List[str]
    info: List[str]


# ---------------------------------------------------------------- DANE (TLSA)

class TlsaRecord(Fixed):
    """One TLSA record of a mail server."""
    host: str = Field(description="The MX host; the record is at _25._tcp.<host>")
    usage: int = Field(description="3 is DANE-EE, 2 is DANE-TA")
    selector: int
    matching_type: int
    certificate: str = Field(description="The certificate association data, in hex")
    record: str = Field(description="'usage selector matching_type data'")


class DaneHost(Fixed):
    """One mail server that publishes TLSA records."""
    host: str
    tlsa_validated: bool = Field(description="Its TLSA records are DNSSEC validated")
    address_validated: Optional[bool] = Field(description="Its A or AAAA records are DNSSEC validated; null when "
                                                          "the lookup failed")
    certificate: str = Field(description="match or mismatch: the certificate it presents on port 25 against its "
                                         "DANE-EE records; not_verifiable (no DANE-EE record), unreachable (no "
                                         "connection) or busy (too many checks at once): not compared")
    certificate_error: str = Field(None, description="Why the certificate could not be read; only for "
                                                     "unreachable and busy")


class TlsaCheck(Fixed):
    """DANE for the domain's mail servers: their TLSA records, whether those are DNSSEC validated and
    match the certificate each one presents. The first 10 MX hosts by preference are checked."""
    status: str = Field(description=STATUS_UNKNOWN + " (such as no MX records or a failed lookup)")
    message: str
    record: Optional[str] = Field(description="Every TLSA record as 'usage selector matching_type data', sorted "
                                              "and joined with ' | '; null without records")
    records: List[TlsaRecord]
    mx_hosts: List[str] = Field(description="The domain's MX hosts; empty when it has none, has a null MX or "
                                            "the lookup failed")
    hosts: List[DaneHost] = Field(None, description="Only when TLSA records were found: each host that "
                                                    "publishes them")
    dane_active: bool = Field(None, description="Only when TLSA records were found: the MX records, TLSA "
                                                "records and addresses are all DNSSEC validated, so senders "
                                                "use them")
    certificate_mismatch: List[str] = Field(None, description="Only when TLSA records were found: the hosts "
                                                              "whose certificate does not match; empty "
                                                              "unless DANE is active")
    not_checked: List[str] = Field(None, description="MX hosts beyond the first 10, which were not checked; "
                                                     "missing when the domain has no MX hosts or the check failed")
    warnings: List[str]
    info: List[str] = Field(None, description="Only when TLSA records were found: the certificate comparison "
                                              "for each host")


# ---------------------------------------------------------------- MTA-STS

class MtaStsCheck(Fixed):
    """MTA-STS (RFC 8461): the record at _mta-sts.<domain>, its policy file, and whether the policy covers
    the domain's MX hosts. It is optional, so without it the status is warning."""
    status: str = Field(description=STATUS_UNKNOWN)
    message: str
    record: Optional[str] = Field(description="Null without a record; every record joined with '; ' when there "
                                              "are several")
    warnings: List[str]
    info: List[str] = Field(None, description="Only when the record is missing (what to publish) and when the "
                                              "policy file is valid (its mode, id, max age and MX)")


# ---------------------------------------------------------------- TLS-RPT

class TlsRptCheck(Fixed):
    """TLS-RPT (RFC 8460): the record at _smtp._tls.<domain> that tells senders where to deliver TLS
    reports. It is optional, so without it the status is warning."""
    status: str = Field(description=STATUS_UNKNOWN)
    message: str
    record: Optional[str] = Field(description="Null without a record; every record joined with '; ' when there "
                                              "are several")
    report_uris: List[str] = Field(description="Its mailto: and https: report addresses")
    warnings: List[str] = Field(description="Such as a report address senders do not deliver to")
    info: List[str] = Field(None, description="Only when the record is missing: what to publish")


# ---------------------------------------------------------------- one domain's check

class DnsCheck(Fixed):
    """Every DNS check of one domain, run at once."""
    domain: str
    spf: SpfCheck
    dkim: DkimCheck
    dmarc: DmarcCheck
    dnssec: DnssecCheck
    tlsa: TlsaCheck = Field(description="DANE")
    mta_sts: MtaStsCheck
    tls_rpt: TlsRptCheck
    checked_at: str = Field(description=TIME)


class DnsCheckFailed(Fixed):
    """The checks could not run together. Each check handles its own failures, so this is not expected."""
    domain: str
    error: str
    checked_at: str = Field(description=TIME)


class StoredDnsChecks(Fixed):
    """The domain's last DNS check, as stored. A check is null when it was not stored, such as a check
    added after the domain was last checked."""
    spf: Optional[SpfCheck]
    dkim: Optional[DkimCheck]
    dmarc: Optional[DmarcCheck]
    dnssec: Optional[DnssecCheck]
    tlsa: Optional[TlsaCheck] = Field(description="DANE")
    mta_sts: Optional[MtaStsCheck]
    tls_rpt: Optional[TlsRptCheck]
    checked_at: str = Field(description="When this domain was last checked, " + TIME)


class NoDnsCheck(Fixed):
    """The domain was not checked yet: an empty object."""


# ---------------------------------------------------------------- GET /domains/all

class AliasDomain(Fixed):
    domain_name: str
    dns_checks: Union[StoredDnsChecks, NoDnsCheck] = Field(description="Its own last DNS check")


class Domain(Fixed):
    """A mailcow domain, its limits and counters as mailcow reports them, and its stored DNS check."""
    domain_name: str
    active: bool
    mboxes_in_domain: Union[int, str] = Field(description=MAILCOW)
    mboxes_left: Union[int, str] = Field(description=MAILCOW)
    max_num_mboxes_for_domain: Union[int, str] = Field(description=MAILCOW)
    aliases_in_domain: Union[int, str] = Field(description=MAILCOW)
    aliases_left: Union[int, str] = Field(description=MAILCOW)
    max_num_aliases_for_domain: Union[int, str] = Field(description=MAILCOW)
    created: Optional[str] = Field(description="When it was created in mailcow, " + TIME + "; mailcow's text "
                                               "when it cannot be read as a date")
    bytes_total: Union[int, str] = Field(description="Storage used, in bytes. " + MAILCOW)
    msgs_total: Union[int, str] = Field(description=MAILCOW)
    quota_used_in_domain: Union[int, str] = Field(description="In bytes. " + MAILCOW)
    max_quota_for_domain: Union[int, str] = Field(description="In bytes; 0 is unlimited. " + MAILCOW)
    backupmx: bool
    relay_all_recipients: bool
    relay_unknown_only: bool
    dns_checks: Union[StoredDnsChecks, NoDnsCheck]
    alias_domains: List[AliasDomain] = Field(description="mailcow alias domains of this domain, with their own "
                                                         "DNS checks")


class DomainsResponse(Fixed):
    """Every mailcow domain with its stored DNS check results."""
    domains: List[Domain]
    total: int
    active: int
    last_dns_check: Optional[str] = Field(description="When every domain was last checked together (the "
                                                      "scheduled check or check-all-dns), " + TIME + "; "
                                                      "checking one domain does not change it")


# ---------------------------------------------------------------- the checks

class CheckAllResponse(Fixed):
    """Every active domain and alias domain was checked and its result stored."""
    status: str = Field(description="success when every domain was checked and stored, else partial")
    message: str
    domains_checked: int
    errors: List[str] = Field(description="One line for each domain that could not be checked or stored")


class CheckOneResponse(Fixed):
    """The domain was checked and its result stored."""
    status: str = Field(description="success")
    message: str
    data: Union[DnsCheck, DnsCheckFailed]
