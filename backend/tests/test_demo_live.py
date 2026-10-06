"""
The demo's live trickle: minute-sized windows get a minute's worth of
traffic, never a line from the future, and the lines a scenario writes later
(a retry, an unban) arrive once their time comes.
"""
import time

from demo import fake_mailcow, seed
from demo.traffic import Batch, Traffic

NOW = 1_790_000_000
TIME_KEY = {"rspamd-history": "unix_time"}


def _windows(traffic, start, minutes):
    for i in range(minutes):
        lo, hi = start + i * 60, start + (i + 1) * 60
        yield lo, hi, traffic.generate(lo, hi, min_weight=seed.LIVE_MIN_WEIGHT,
                                       noise_per_minute=seed.LIVE_NOISE_PER_MINUTE)


def test_minute_windows_never_contain_future_lines():
    traffic = Traffic(seed=7)
    for lo, hi, batch in _windows(traffic, NOW, 180):
        for service, entries in batch.items():
            for e in entries:
                assert int(e[TIME_KEY.get(service, "time")]) < hi, service


def test_lines_written_later_arrive_in_a_later_window():
    traffic = Traffic(seed=7)
    batch = Batch()
    # 26 attempts 17 seconds apart, starting 30 seconds before the window ends
    traffic.credential_attack(batch, NOW + 30)
    first = traffic._release(batch, NOW + 60)["netfilter"]
    later = traffic.generate(NOW + 60, NOW + 600)["netfilter"]
    attack = [e for e in first + later if "admin@example.com" in e["message"]]
    assert 0 < len(first) < 26
    assert len(attack) == 26
    assert all(int(e["time"]) >= NOW + 60 for e in later)


def test_the_trickle_rate_is_steady_at_any_hour():
    traffic = Traffic(seed=3)
    busy = [sum(len(v) for v in batch.values()) for _, _, batch in _windows(traffic, NOW, 120)]
    # Connection noise alone arrives in most minutes
    assert sum(1 for n in busy if n) > 0.7 * len(busy)
    messages = sum(len(batch["rspamd-history"]) for _, _, batch in _windows(Traffic(seed=3), NOW, 120))
    assert 10 <= messages <= 60  # about twelve an hour


def test_queue_ids_stay_unique_across_history_and_live():
    traffic = Traffic(seed=11)
    history = traffic.generate(NOW - 2 * 86400, NOW)
    live = [b for _, _, b in _windows(traffic, NOW, 60)]
    ids = [e["qid"] for e in history["rspamd-history"]] + [e["qid"] for b in live for e in b["rspamd-history"]]
    assert len(ids) == len(set(ids))


def test_the_live_loop_feeds_the_fake_server():
    fake = fake_mailcow.FakeMailcow()
    seed.start_live_traffic(fake, Traffic(seed=5), interval=0.05)
    deadline = time.time() + 5
    while time.time() < deadline and not any(fake.logs.values()):
        time.sleep(0.05)
    assert any(fake.logs.values())
