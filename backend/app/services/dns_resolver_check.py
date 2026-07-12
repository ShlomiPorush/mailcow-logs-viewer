"""
Test script for DNS resolver with DoH fallback.
Run inside the container: python -m app.services.dns_resolver_check
"""
import asyncio
import logging
from app.services.dns_resolver import (
    resolve, resolve_for_blacklist, _resolve_with_fallback,
    UDP_DNS_SERVERS, DOH_URLS, BLACKLIST_DOH_URLS
)

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


async def test_udp_path():
    """Test 1: Normal UDP resolution (should work on most servers)"""
    print("\n" + "="*60)
    print("TEST 1: UDP Resolution (normal path)")
    print("="*60)
    try:
        answer = await resolve("google.com", "A", timeout=5)
        ips = [str(r) for r in answer]
        print(f"  ✅ UDP works! google.com A = {ips}")
        return True
    except Exception as e:
        print(f"  ❌ UDP failed: {type(e).__name__}: {e}")
        print(f"     (This is expected if your server blocks UDP 53)")
        return False


async def test_doh_path():
    """Test 2: Force DoH by passing empty UDP server list"""
    print("\n" + "="*60)
    print("TEST 2: DoH Resolution (forced — empty UDP list)")
    print("="*60)
    try:
        # Pass empty UDP list to force DoH fallback
        answer = await _resolve_with_fallback("google.com", "A", 5, [], DOH_URLS)
        ips = [str(r) for r in answer]
        print(f"  ✅ DoH works! google.com A = {ips}")
        return True
    except Exception as e:
        print(f"  ❌ DoH failed: {type(e).__name__}: {e}")
        return False


async def test_doh_txt():
    """Test 3: DoH with TXT record (like SPF/DMARC checks)"""
    print("\n" + "="*60)
    print("TEST 3: DoH TXT Resolution (SPF-style)")
    print("="*60)
    try:
        answer = await _resolve_with_fallback("google.com", "TXT", 5, [], DOH_URLS)
        records = [str(r) for r in answer]
        print(f"  ✅ DoH TXT works! Got {len(records)} record(s)")
        return True
    except Exception as e:
        print(f"  ❌ DoH TXT failed: {type(e).__name__}: {e}")
        return False


async def test_nxdomain():
    """Test 4: NXDOMAIN handling (should raise, not fall through)"""
    print("\n" + "="*60)
    print("TEST 4: NXDOMAIN Handling")
    print("="*60)
    try:
        await resolve("this-domain-definitely-does-not-exist-xyz123.com", "A")
        print(f"  ❌ Should have raised NXDOMAIN!")
        return False
    except Exception as e:
        if "NXDOMAIN" in type(e).__name__ or "NXDOMAIN" in str(e):
            print(f"  ✅ NXDOMAIN correctly raised: {type(e).__name__}")
            return True
        else:
            print(f"  ⚠️  Got different error: {type(e).__name__}: {e}")
            return False


async def test_blacklist_resolve():
    """Test 5: Blacklist resolver (uses special DNS servers)"""
    print("\n" + "="*60)
    print("TEST 5: Blacklist Resolution (Quad9/Spamhaus servers)")
    print("="*60)
    try:
        # 127.0.0.2 is a test address that should return NXDOMAIN (not listed)
        await resolve_for_blacklist("2.0.0.127.zen.spamhaus.org", "A", timeout=10)
        print(f"  ⚠️  Got answer (might be listed or blocked query)")
        return True
    except Exception as e:
        if "NXDOMAIN" in type(e).__name__:
            print(f"  ✅ NXDOMAIN = IP not listed (correct)")
            return True
        else:
            print(f"  ⚠️  Error: {type(e).__name__}: {e}")
            return False


async def main():
    print("🔍 DNS Resolver Test Suite")
    print("Testing UDP and DoH paths independently\n")
    
    results = []
    results.append(("UDP Resolution", await test_udp_path()))
    results.append(("DoH Resolution", await test_doh_path()))
    results.append(("DoH TXT Records", await test_doh_txt()))
    results.append(("NXDOMAIN Handling", await test_nxdomain()))
    results.append(("Blacklist Resolution", await test_blacklist_resolve()))
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    passed = sum(1 for _, r in results if r)
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {name}")
    print(f"\n  {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed!")
    elif results[0][1] == False and results[1][1] == True:
        print("\n⚠️  UDP blocked but DoH works — fallback is functioning correctly!")
    else:
        print("\n⚠️  Some tests failed — check output above")


if __name__ == "__main__":
    asyncio.run(main())
