"""The one reading of an IP address, an email address and a domain that the
entity card, the watchlist and the search share (services/entity_values.py)."""
import pytest

from app.services import entity_values as ev
from app.services.entity_values import InvalidValue


# ---------------------------------------------------------------- IP

@pytest.mark.parametrize("given,expected", [
    ("203.0.113.4", "203.0.113.4"),
    ("  203.0.113.4\n", "203.0.113.4"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:db8::ff00:42:8329"),
    ("::ffff:203.0.113.4", "203.0.113.4"),          # an IPv4 client seen over IPv6 is the IPv4 address
    ("::1", "::1"),
])
def test_ip_is_written_canonically(given, expected):
    assert ev.normalize_ip(given) == expected


@pytest.mark.parametrize("given,says", [
    ("fe80::1%eth0", "interface"),
    ("203.0.113.0/24", "not a network"),
    ("203.0.113.4/32", "not a network"),
    ("2001:db8::/64", "not a network"),
    ("203.0.113.256", "one IP address"),
    ("203.0.113.04", "one IP address"),               # a leading zero is refused by ipaddress
    ("example.com", "one IP address"),
    ("203.0.113.4 203.0.113.5", "without spaces"),
    ("203.0.113.4\x00", "without spaces"),
    ("", "Enter one IP address"),
    ("1" * 65, "too long"),
])
def test_ip_refuses_what_is_not_one_address(given, says):
    with pytest.raises(InvalidValue) as e:
        ev.normalize_ip(given)
    assert says in str(e.value)


def test_ip_forms_cover_how_other_systems_write_ipv6():
    forms = ev.ip_forms("2001:db8::1")
    assert "2001:db8::1" in forms and "2001:0db8:0000:0000:0000:0000:0000:0001" in forms
    assert "2001:DB8::1" in forms
    assert ev.ip_forms("203.0.113.4") == ["203.0.113.4"]


# ---------------------------------------------------------------- address

@pytest.mark.parametrize("given,expected", [
    ("Ann@Example.COM", "ann@example.com"),
    ("ann+news@example.com", "ann+news@example.com"),
    ("a/b@example.com", "a/b@example.com"),
    ('"ann"@example.com', '"ann"@example.com'),
    ('"a@b"@example.com', '"a@b"@example.com'),          # split on the last @
    ("o'brien@example.com", "o'brien@example.com"),
    ("ann_100%@example.com", "ann_100%@example.com"),
    ("ann@example.com.", "ann@example.com"),
    ("ann@Bücher.example", "ann@xn--bcher-kva.example"),
    ("  ann@example.com  ", "ann@example.com"),
])
def test_address_lookup_form(given, expected):
    normalized, display = ev.normalize_address(given)
    assert normalized == expected
    assert display == given.strip()


@pytest.mark.parametrize("given", [
    "ann", "@example.com", "ann@", "ann@example", "ann@203.0.113.4", "ann @example.com",
    "ann@exa​mple.com", "ann\x07@example.com", "ann@ex ample.com", "ann@-example.com",
    "a" * 65 + "@example.com", "a@" + ("b" * 60 + ".") * 5 + "com", "ann@exa..mple.com", "",
])
def test_address_refuses_what_is_not_one_address(given):
    with pytest.raises(InvalidValue):
        ev.normalize_address(given)


def test_address_length_limit_is_254():
    local = "a" * 64
    domain = ".".join(["b" * 61] * 3) + ".com"      # 189 characters
    assert len(f"{local}@{domain}") == 254
    assert ev.normalize_address(f"{local}@{domain}")[0] == f"{local}@{domain}"
    with pytest.raises(InvalidValue) as e:
        ev.normalize_address(f"{local}@c{domain}")
    assert "too long" in str(e.value)


def test_address_forms_hold_both_forms_of_an_idn_domain():
    assert ev.address_forms("ann@xn--bcher-kva.example") == ["ann@xn--bcher-kva.example", "ann@bücher.example"]
    assert ev.address_forms("ann@example.com") == ["ann@example.com"]


# ---------------------------------------------------------------- domain

@pytest.mark.parametrize("given,expected", [
    ("Example.COM", "example.com"),
    ("example.com.", "example.com"),
    ("mail.example.com", "mail.example.com"),
    ("Bücher.example", "xn--bcher-kva.example"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ("_dmarc.example.com", "_dmarc.example.com"),
])
def test_domain_lookup_form(given, expected):
    assert ev.normalize_domain(given) == expected


@pytest.mark.parametrize("given", [
    "example", "203.0.113.4", "ann@example.com", "exa mple.com", "example..com", "-example.com",
    "example.com..", "exa\tmple.com", ("a" * 63 + ".") * 4 + "com", "a" * 64 + ".com", "example.com/x", "",
])
def test_domain_refuses_what_is_not_one_domain(given):
    with pytest.raises(InvalidValue):
        ev.normalize_domain(given)


def test_domain_forms():
    assert ev.domain_forms("xn--bcher-kva.example") == ["xn--bcher-kva.example", "bücher.example"]


# ---------------------------------------------------------------- detect_kind

@pytest.mark.parametrize("given,kind", [
    ("203.0.113.4", "ip"), ("2001:db8::1", "ip"), ("ann@example.com", "address"),
    ("example.com", "domain"), ("Bücher.example", "domain"), ("203.0.113.0/24", None),
    ("hello", None), ("ann@", None), ("", None), (None, None),
])
def test_detect_kind(given, kind):
    assert ev.detect_kind(given) == kind


# ---------------------------------------------------------------- Fail2ban list entry

@pytest.mark.parametrize("value", ["203.0.113.4", "203.0.113.4/32", "198.51.100.0/24", "198.51.100.7/24",
                                   "2001:db8::7", "2001:db8::7/128", "2001:db8::/48"])
def test_fail2ban_entry_accepts_one_address_or_network(value):
    assert ev.fail2ban_entry_problem(value) is None


@pytest.mark.parametrize("value", ["203.0.113.4,0.0.0.0/0", "203.0.113.4\n198.51.100.1", " 203.0.113.4",
                                   "203.0.113.4/255.255.255.0", "203.0.113.4/", "fe80::1%eth0",
                                   "mail.example.com", "203.0.113.4/33", "", None, 7])
def test_fail2ban_entry_refuses_anything_else(value):
    assert ev.fail2ban_entry_problem(value)
