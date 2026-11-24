import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session, load_only

from .database import SessionLocal
from .models import MessageCorrelation, PostfixLog, RspamdLog

logger = logging.getLogger(__name__)


_MERGED_COLUMNS = (
    MessageCorrelation.id, MessageCorrelation.correlation_key, MessageCorrelation.message_id,
    MessageCorrelation.queue_id, MessageCorrelation.postfix_log_ids, MessageCorrelation.rspamd_log_id,
    MessageCorrelation.sender, MessageCorrelation.recipient, MessageCorrelation.subject,
    MessageCorrelation.direction, MessageCorrelation.final_status, MessageCorrelation.first_seen,
    MessageCorrelation.last_seen,
)


def cleanup_duplicate_correlations(db: Session) -> int:
    logger.info("Checking for duplicate correlations by Message-ID and Queue-ID...")

    try:
        query = text("""
            SELECT message_id, queue_id, array_agg(correlation_key ORDER BY first_seen) as keys, COUNT(*) as count
            FROM message_correlations
            WHERE message_id IS NOT NULL AND message_id != ''
            GROUP BY message_id, queue_id
            HAVING COUNT(*) > 1
        """)

        result = db.execute(query)
        duplicates = result.fetchall()

        if not duplicates:
            logger.info("No duplicate correlations found")
            return 0

        logger.info(f"Found {len(duplicates)} deliveries with duplicate correlations")

        has_written = db.execute(text(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
            "AND table_name = 'message_correlations' AND column_name = 'written_recipients'")).first() is not None
        columns = _MERGED_COLUMNS + ((MessageCorrelation.written_recipients,) if has_written else ())

        total_removed = 0
        for message_id, queue_id, correlation_keys, count in duplicates:
            leg_filter = (
                MessageCorrelation.queue_id == queue_id if queue_id
                else MessageCorrelation.queue_id.is_(None)
            )
            correlations = db.query(MessageCorrelation).options(load_only(*columns)).filter(
                MessageCorrelation.message_id == message_id,
                leg_filter
            ).order_by(MessageCorrelation.first_seen, MessageCorrelation.id).all()

            if len(correlations) <= 1:
                continue
            
            primary = correlations[0]
            duplicates_to_remove = correlations[1:]
            
            logger.info(f"Merging {len(duplicates_to_remove)} duplicate correlations for Message-ID {message_id[:50]}")
            
            all_postfix_ids = set(primary.postfix_log_ids or [])
            
            for dup in duplicates_to_remove:
                if dup.postfix_log_ids:
                    all_postfix_ids.update(dup.postfix_log_ids)
                
                if not primary.rspamd_log_id and dup.rspamd_log_id:
                    primary.rspamd_log_id = dup.rspamd_log_id
                
                if not primary.queue_id and dup.queue_id:
                    primary.queue_id = dup.queue_id
                
                if not primary.sender and dup.sender:
                    primary.sender = dup.sender
                
                if not primary.recipient and dup.recipient:
                    primary.recipient = dup.recipient
                
                if not primary.subject and dup.subject:
                    primary.subject = dup.subject
                
                if not primary.direction and dup.direction:
                    primary.direction = dup.direction
                
                if dup.last_seen > primary.last_seen:
                    primary.last_seen = dup.last_seen
                
                if dup.final_status:
                    if dup.final_status in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'deferred' and primary.final_status not in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'spam' and primary.final_status not in ['bounced', 'rejected', 'deferred']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'delivered' and not primary.final_status:
                        primary.final_status = dup.final_status
            
            primary.postfix_log_ids = sorted(list(all_postfix_ids))

            if has_written:
                written = {}
                for row in reversed(correlations):
                    if isinstance(row.written_recipients, dict):
                        written.update(row.written_recipients)
                if written:
                    primary.written_recipients = written
            
            if all_postfix_ids:
                db.query(PostfixLog).filter(
                    PostfixLog.id.in_(all_postfix_ids)
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            if primary.rspamd_log_id:
                db.query(RspamdLog).filter(
                    RspamdLog.id == primary.rspamd_log_id
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            for dup in duplicates_to_remove:
                db.delete(dup)
                total_removed += 1
        
        db.commit()
        logger.info(f"Cleanup complete: Removed {total_removed} duplicate correlations")
        return total_removed
        
    except Exception as e:
        logger.error(f"Error during duplicate cleanup: {e}")
        db.rollback()
        return 0


def add_message_id_indexes(db: Session):
    logger.info("Ensuring Message-ID indexes exist...")
    
    try:
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_postfix_message_id 
            ON postfix_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_rspamd_message_id 
            ON rspamd_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_correlation_message_id 
            ON message_correlations (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        db.commit()
        logger.info("Message-ID indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")
        db.rollback()


def add_is_complete_column(db: Session):
    logger.info("Checking if is_complete column exists...")
    
    try:
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='message_correlations' 
            AND column_name='is_complete'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding is_complete column...")
            
            db.execute(text("""
                ALTER TABLE message_correlations 
                ADD COLUMN is_complete BOOLEAN DEFAULT FALSE
            """))
            
            db.execute(text("""
                CREATE INDEX idx_correlation_is_complete 
                ON message_correlations (is_complete)
            """))
            
            db.execute(text("""
                UPDATE message_correlations 
                SET is_complete = TRUE 
                WHERE queue_id IS NOT NULL 
                AND postfix_log_ids IS NOT NULL 
                AND array_length(postfix_log_ids, 1) > 0
            """))
            
            db.commit()
            logger.info("is_complete column added and existing data updated")
        else:
            logger.info("is_complete column already exists")
        
    except Exception as e:
        logger.error(f"Error adding is_complete column: {e}")
        db.rollback()


def add_is_full_check_column(db: Session):
    logger.info("Checking if is_full_check column exists...")
    
    try:
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='domain_dns_checks' 
            AND column_name='is_full_check'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding is_full_check column...")
            db.execute(text("""
                ALTER TABLE domain_dns_checks 
                ADD COLUMN is_full_check BOOLEAN DEFAULT FALSE
            """))
            db.commit()
            logger.info("is_full_check column added")
        else:
            logger.info("is_full_check column already exists")
        
    except Exception as e:
        logger.error(f"Error adding is_full_check column: {e}")
        db.rollback()

def add_postfix_unique_constraint(db: Session):
    logger.info("Adding UNIQUE constraint to postfix_logs...")
    
    try:
        result = db.execute(text("""
            SELECT indexname 
            FROM pg_indexes 
            WHERE tablename='postfix_logs' 
            AND indexname='uq_postfix_log'
        """))
        
        if result.fetchone():
            logger.info("UNIQUE index already exists, skipping...")
            return
        
        logger.info("Cleaning up duplicate Postfix logs...")
        
        result = db.execute(text("""
            DELETE FROM postfix_logs
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY time, program, COALESCE(queue_id, ''), message
                               ORDER BY created_at ASC
                           ) as row_num
                    FROM postfix_logs
                ) t
                WHERE t.row_num > 1
            )
        """))
        
        deleted = result.rowcount
        db.commit()
        
        if deleted > 0:
            logger.info(f"Deleted {deleted} duplicate Postfix logs")
        else:
            logger.info("No duplicate Postfix logs found")
        
        logger.info("Creating UNIQUE index...")
        db.execute(text("""
            CREATE UNIQUE INDEX uq_postfix_log 
            ON postfix_logs (time, program, COALESCE(queue_id, ''), message);
        """))
        
        db.commit()
        logger.info("✓ UNIQUE index added successfully")
        
    except Exception as e:
        error_msg = str(e).lower()
        if "already exists" in error_msg or "duplicate" in error_msg:
            logger.info("UNIQUE index already exists, skipping...")
            db.rollback()
        elif "deadlock" in error_msg or "lock" in error_msg:
            logger.warning(f"Could not add UNIQUE index due to lock (will retry on next startup): {e}")
            db.rollback()
        else:
            logger.error(f"Error adding UNIQUE index: {e}")
            db.rollback()

def add_geoip_fields_to_dmarc(db: Session):
    logger.info("Checking if GeoIP fields exist in dmarc_records...")
    
    try:
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='dmarc_records' 
            AND column_name='country_code'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding GeoIP fields to dmarc_records...")
            
            db.execute(text("""
                ALTER TABLE dmarc_records 
                ADD COLUMN country_code VARCHAR(2),
                ADD COLUMN country_name VARCHAR(100),
                ADD COLUMN country_emoji VARCHAR(10),
                ADD COLUMN city VARCHAR(100),
                ADD COLUMN asn VARCHAR(20),
                ADD COLUMN asn_org VARCHAR(255);
            """))
            
            db.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_dmarc_record_country 
                ON dmarc_records(country_code);
            """))
            
            db.commit()
            logger.info("✓ GeoIP fields added to dmarc_records")
        else:
            logger.info("✓ GeoIP fields already exist in dmarc_records")
        
    except Exception as e:
        logger.error(f"Error adding GeoIP fields: {e}")
        db.rollback()

def add_geoip_fields_to_rspamd(db: Session):
    logger.info("Checking if GeoIP fields exist in rspamd_logs...")
    
    try:
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='rspamd_logs' 
            AND column_name='country_code'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding GeoIP fields to rspamd_logs...")
            
            db.execute(text("""
                ALTER TABLE rspamd_logs 
                ADD COLUMN country_code VARCHAR(2),
                ADD COLUMN country_name VARCHAR(100),
                ADD COLUMN city VARCHAR(100),
                ADD COLUMN asn VARCHAR(20),
                ADD COLUMN asn_org VARCHAR(255);
            """))
            
            db.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rspamd_country 
                ON rspamd_logs(country_code);
            """))
            
            db.commit()
            logger.info("✓ GeoIP fields added to rspamd_logs")
        else:
            logger.info("✓ GeoIP fields already exist in rspamd_logs")
        
    except Exception as e:
        logger.error(f"Error adding GeoIP fields to rspamd_logs: {e}")
        db.rollback()

def add_geoip_fields_to_netfilter(db: Session):
    logger.info("Checking if GeoIP fields exist in netfilter_logs...")
    
    try:
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='netfilter_logs' 
            AND column_name='country_code'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding GeoIP fields to netfilter_logs...")
            
            db.execute(text("""
                ALTER TABLE netfilter_logs 
                ADD COLUMN country_code VARCHAR(2),
                ADD COLUMN country_name VARCHAR(100),
                ADD COLUMN city VARCHAR(100),
                ADD COLUMN asn VARCHAR(20),
                ADD COLUMN asn_org VARCHAR(255);
            """))
            
            db.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_netfilter_country 
                ON netfilter_logs(country_code);
            """))
            
            db.commit()
            logger.info("✓ GeoIP fields added to netfilter_logs")
        else:
            logger.info("✓ GeoIP fields already exist in netfilter_logs")
        
    except Exception as e:
        logger.error(f"Error adding GeoIP fields to netfilter_logs: {e}")
        db.rollback()

def backfill_geoip_netfilter(db: Session):
    from .services import geoip_service as _geoip_service
    
    if not _geoip_service.is_geoip_available():
        return
    
    try:
        result = db.execute(text("""
            SELECT COUNT(*) FROM netfilter_logs 
            WHERE ip IS NOT NULL AND country_code IS NULL
        """))
        count = result.scalar()
        
        if count == 0:
            return
        
        logger.info(f"Backfilling GeoIP data for {count} netfilter logs...")
        
        batch_size = 500
        updated = 0
        rows = db.execute(text("""
            SELECT id, ip FROM netfilter_logs 
            WHERE ip IS NOT NULL AND country_code IS NULL
            LIMIT :limit
        """), {"limit": batch_size}).fetchall()
        
        while rows:
            for row in rows:
                geo = _geoip_service.lookup_ip(row.ip)
                country_code = geo.get('country_code') or 'ZZ'

                db.execute(text("""
                    UPDATE netfilter_logs
                    SET country_code = :cc,
                        country_name = :cn,
                        city = :city,
                        asn = :asn,
                        asn_org = :ao
                    WHERE id = :id
                """), {
                    "cc": country_code,
                    "cn": geo.get('country_name') or 'Unknown',
                    "city": geo.get('city'),
                    "asn": geo.get('asn'),
                    "ao": geo.get('asn_org'),
                    "id": row.id
                })

                updated += 1
            
            db.commit()
            
            rows = db.execute(text("""
                SELECT id, ip FROM netfilter_logs 
                WHERE ip IS NOT NULL AND country_code IS NULL
                LIMIT :limit
            """), {"limit": batch_size}).fetchall()
        
        if updated > 0:
            logger.info(f"✓ Backfilled GeoIP data for {updated} netfilter logs")
    
    except Exception as e:
        logger.error(f"Error backfilling GeoIP for netfilter: {e}")
        db.rollback()

def create_dmarc_sync_table(db: Session):
    logger.info("Checking if dmarc_syncs table exists...")
    
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'dmarc_syncs'
            );
        """))
        
        table_exists = result.scalar()
        
        if table_exists:
            logger.info("✓ dmarc_syncs table already exists")
            return
        
        logger.info("Creating dmarc_syncs table...")
        
        db.execute(text("""
            CREATE TABLE dmarc_syncs (
                id SERIAL PRIMARY KEY,
                sync_type VARCHAR(20) NOT NULL,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                status VARCHAR(20) NOT NULL,
                
                emails_found INTEGER DEFAULT 0,
                emails_processed INTEGER DEFAULT 0,
                reports_created INTEGER DEFAULT 0,
                reports_duplicate INTEGER DEFAULT 0,
                reports_failed INTEGER DEFAULT 0,
                
                error_message TEXT,
                failed_emails JSONB,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        
        db.execute(text("""
            CREATE INDEX idx_dmarc_sync_type_status 
            ON dmarc_syncs(sync_type, status);
        """))
        
        db.execute(text("""
            CREATE INDEX idx_dmarc_sync_started 
            ON dmarc_syncs(started_at);
        """))
        
        db.commit()
        logger.info("✓ dmarc_syncs table created successfully")
        
    except Exception as e:
        logger.error(f"Error creating dmarc_syncs table: {e}")
        db.rollback()
        raise

def ensure_mailbox_statistics_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'mailbox_statistics'
            )
        """)).scalar()
        
        if not result:
            logger.info("Creating mailbox_statistics table...")
            db.execute(text("""
                CREATE TABLE mailbox_statistics (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    name VARCHAR(255),
                    quota BIGINT DEFAULT 0,
                    quota_used BIGINT DEFAULT 0,
                    percent_in_use FLOAT DEFAULT 0.0,
                    messages INTEGER DEFAULT 0,
                    active BOOLEAN DEFAULT TRUE,
                    last_imap_login BIGINT,
                    last_pop3_login BIGINT,
                    last_smtp_login BIGINT,
                    spam_aliases INTEGER DEFAULT 0,
                    rl_value INTEGER,
                    rl_frame VARCHAR(20),
                    attributes JSONB,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_mailbox_domain ON mailbox_statistics(domain)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_mailbox_active ON mailbox_statistics(active)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_mailbox_quota_used ON mailbox_statistics(quota_used)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_mailbox_username ON mailbox_statistics(username)"))
            
            db.commit()
            logger.info("mailbox_statistics table created successfully")
        else:
            logger.debug("mailbox_statistics table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring mailbox_statistics table: {e}")
        db.rollback()
        raise


def widen_monitored_hosts_source(db: Session):
    try:
        result = db.execute(text("""
            SELECT character_maximum_length
            FROM information_schema.columns
            WHERE table_name='monitored_hosts'
            AND column_name='source'
        """)).fetchone()

        if result and result[0] is not None:
            logger.info(f"Widening monitored_hosts.source from VARCHAR({result[0]}) to TEXT...")
            db.execute(text("""
                ALTER TABLE monitored_hosts
                ALTER COLUMN source TYPE TEXT
            """))
            db.commit()
            logger.info("monitored_hosts.source widened to TEXT")

    except Exception as e:
        logger.error(f"Failed to widen monitored_hosts.source: {e}")
        db.rollback()


def run_migrations():
    logger.info("Running database migrations...")
    
    db = SessionLocal()
    try:
        add_message_id_indexes(db)
        
        add_is_complete_column(db)
        
        add_is_full_check_column(db)

        add_postfix_unique_constraint(db)

        removed = cleanup_duplicate_correlations(db)

        create_dmarc_sync_table(db)

        add_geoip_fields_to_dmarc(db)
        
        ensure_mailbox_statistics_table(db)
        
        ensure_alias_statistics_table(db)

        ensure_system_settings_table(db)
        
        ensure_known_containers_table(db)
        
        ensure_raw_service_logs_table(db)
        
        ensure_spam_suppressions_table(db)

        widen_monitored_hosts_source(db)

        add_geoip_fields_to_rspamd(db)
        add_geoip_fields_to_netfilter(db)
        backfill_geoip_netfilter(db)
        
        if removed > 0:
            logger.info(f"Migration complete: Cleaned up {removed} duplicate correlations")
        else:
            logger.info("Migration complete: No duplicates found")
            
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        db.close()


def ensure_alias_statistics_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'alias_statistics'
            )
        """))
        table_exists = result.scalar()
        
        if not table_exists:
            logger.info("Creating alias_statistics table...")
            db.execute(text("""
                CREATE TABLE alias_statistics (
                    id SERIAL PRIMARY KEY,
                    alias_address VARCHAR(255) NOT NULL UNIQUE,
                    goto TEXT,
                    domain VARCHAR(255) NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    is_catch_all BOOLEAN DEFAULT FALSE,
                    primary_mailbox VARCHAR(255),
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_alias_domain ON alias_statistics(domain)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_alias_active ON alias_statistics(active)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_alias_primary_mailbox ON alias_statistics(primary_mailbox)"))
            db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_alias_address ON alias_statistics(alias_address)"))
            
            db.commit()
            logger.info("alias_statistics table created successfully")
        else:
            logger.debug("alias_statistics table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring alias_statistics table: {e}")
        db.rollback()
        raise


def ensure_system_settings_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'system_settings'
            )
        """))
        table_exists = result.scalar()
        
        if not table_exists:
            logger.info("Creating system_settings table...")
            db.execute(text("""
                CREATE TABLE system_settings (
                    key VARCHAR(255) PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            
            db.commit()
            logger.info("system_settings table created successfully")
        else:
            logger.debug("system_settings table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring system_settings table: {e}")
        db.rollback()
        raise


def ensure_known_containers_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'known_containers'
            )
        """))
        table_exists = result.scalar()
        
        if not table_exists:
            logger.info("Creating known_containers table...")
            db.execute(text("""
                CREATE TABLE known_containers (
                    container_name VARCHAR(255) PRIMARY KEY,
                    display_name VARCHAR(255) NOT NULL,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_known_containers_last_seen ON known_containers(last_seen)"))
            
            db.commit()
            logger.info("known_containers table created successfully")
        else:
            logger.debug("known_containers table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring known_containers table: {e}")
        db.rollback()
        raise


def ensure_raw_service_logs_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'raw_service_logs'
            )
        """))
        table_exists = result.scalar()
        
        if not table_exists:
            logger.info("Creating raw_service_logs table...")
            db.execute(text("""
                CREATE TABLE raw_service_logs (
                    id SERIAL PRIMARY KEY,
                    service VARCHAR(50) NOT NULL,
                    time TIMESTAMP NOT NULL,
                    message_hash VARCHAR(64) NOT NULL,
                    raw_data JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    CONSTRAINT uq_raw_service_log UNIQUE (service, time, message_hash)
                )
            """))
            
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_raw_log_service_time ON raw_service_logs(service, time DESC)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_raw_log_time ON raw_service_logs(time)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_raw_log_service ON raw_service_logs(service)"))
            
            db.commit()
            logger.info("raw_service_logs table created successfully")
        else:
            logger.debug("raw_service_logs table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring raw_service_logs table: {e}")
        db.rollback()
        raise


def ensure_spam_suppressions_table(db: Session):
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'spam_suppressions'
            )
        """))
        table_exists = result.scalar()
        
        if not table_exists:
            logger.info("Creating spam_suppressions table...")
            db.execute(text("""
                CREATE TABLE spam_suppressions (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    type VARCHAR(20) NOT NULL DEFAULT 'email',
                    reason VARCHAR(50) NOT NULL,
                    source VARCHAR(100),
                    notes TEXT,
                    bounce_count INTEGER DEFAULT 1,
                    hard_bounce_count INTEGER DEFAULT 0,
                    soft_bounce_count INTEGER DEFAULT 0,
                    last_bounce_dsn VARCHAR(20),
                    last_bounce_message TEXT,
                    correlation_key VARCHAR(64),
                    active BOOLEAN DEFAULT TRUE,
                    synced_to_rspamd BOOLEAN DEFAULT FALSE,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_email ON spam_suppressions(email)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_type ON spam_suppressions(type)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_reason ON spam_suppressions(reason)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_active ON spam_suppressions(active)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_active_sync ON spam_suppressions(active, synced_to_rspamd)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_suppression_expires ON spam_suppressions(active, expires_at)"))
            
            db.commit()
            logger.info("spam_suppressions table created successfully")
        else:
            logger.debug("spam_suppressions table already exists")
            
    except Exception as e:
        logger.error(f"Error ensuring spam_suppressions table: {e}")
        db.rollback()
        raise


def run_alembic_upgrade():
    from alembic import command
    from alembic.config import Config as AlembicConfig

    ini_path = Path(__file__).resolve().parent.parent / "alembic.ini"
    if not ini_path.exists():
        raise FileNotFoundError(f"alembic.ini not found at {ini_path}")

    cfg = AlembicConfig(str(ini_path))
    cfg.set_main_option("script_location", str(ini_path.parent / "alembic"))
    # without %% a database password containing % breaks ConfigParser interpolation
    from .config import settings
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))

    command.upgrade(cfg, "head")
    logger.info("Alembic schema is up to date")
