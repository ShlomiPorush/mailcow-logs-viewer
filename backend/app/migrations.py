"""
Database migrations and maintenance utilities

SIMPLIFIED VERSION:
- Clean up duplicate correlations by Message-ID (not Queue-ID)
- Merge duplicates into the oldest one
- Update all related logs
"""
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import MessageCorrelation, PostfixLog, RspamdLog

logger = logging.getLogger(__name__)


def cleanup_duplicate_correlations(db: Session) -> int:
    """
    Clean up duplicate correlations that share the same Message-ID
    
    With the new Message-ID-based approach, there should be only ONE
    correlation per Message-ID. This function merges any duplicates.
    
    Strategy:
    1. Find Message-IDs with multiple correlations
    2. For each, keep the oldest correlation
    3. Merge postfix_log_ids and rspamd_log_id from duplicates
    4. Update all related logs to point to the kept correlation
    5. Delete the duplicates
    
    Returns:
        Number of duplicate correlations removed
    """
    logger.info("Checking for duplicate correlations by Message-ID...")
    
    try:
        # Find Message-IDs with multiple correlations
        query = text("""
            SELECT message_id, array_agg(correlation_key ORDER BY first_seen) as keys, COUNT(*) as count
            FROM message_correlations
            WHERE message_id IS NOT NULL AND message_id != ''
            GROUP BY message_id
            HAVING COUNT(*) > 1
        """)
        
        result = db.execute(query)
        duplicates = result.fetchall()
        
        if not duplicates:
            logger.info("No duplicate correlations found")
            return 0
        
        logger.info(f"Found {len(duplicates)} Message-IDs with duplicate correlations")
        
        total_removed = 0
        for message_id, correlation_keys, count in duplicates:
            # Get all correlations for this Message-ID (ordered by first_seen)
            correlations = db.query(MessageCorrelation).filter(
                MessageCorrelation.message_id == message_id
            ).order_by(MessageCorrelation.first_seen).all()
            
            if len(correlations) <= 1:
                continue
            
            # Keep the first (oldest) correlation
            primary = correlations[0]
            duplicates_to_remove = correlations[1:]
            
            logger.info(f"Merging {len(duplicates_to_remove)} duplicate correlations for Message-ID {message_id[:50]}")
            
            # Merge data from duplicates into primary
            all_postfix_ids = set(primary.postfix_log_ids or [])
            
            for dup in duplicates_to_remove:
                # Merge postfix_log_ids
                if dup.postfix_log_ids:
                    all_postfix_ids.update(dup.postfix_log_ids)
                
                # Update rspamd_log_id if primary doesn't have one
                if not primary.rspamd_log_id and dup.rspamd_log_id:
                    primary.rspamd_log_id = dup.rspamd_log_id
                
                # Update queue_id if primary doesn't have one
                if not primary.queue_id and dup.queue_id:
                    primary.queue_id = dup.queue_id
                
                # Update sender if missing
                if not primary.sender and dup.sender:
                    primary.sender = dup.sender
                
                # Update recipient if missing
                if not primary.recipient and dup.recipient:
                    primary.recipient = dup.recipient
                
                # Update subject if missing
                if not primary.subject and dup.subject:
                    primary.subject = dup.subject
                
                # Update direction if missing
                if not primary.direction and dup.direction:
                    primary.direction = dup.direction
                
                # Update timestamps if needed
                if dup.last_seen > primary.last_seen:
                    primary.last_seen = dup.last_seen
                
                # Update status (priority: bounced > rejected > deferred > spam > delivered)
                if dup.final_status:
                    if dup.final_status in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'deferred' and primary.final_status not in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'spam' and primary.final_status not in ['bounced', 'rejected', 'deferred']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'delivered' and not primary.final_status:
                        primary.final_status = dup.final_status
            
            # Update primary correlation with merged data
            primary.postfix_log_ids = sorted(list(all_postfix_ids))
            
            # Update all Postfix logs to point to the primary correlation
            if all_postfix_ids:
                db.query(PostfixLog).filter(
                    PostfixLog.id.in_(all_postfix_ids)
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            # Update Rspamd log to point to the primary correlation
            if primary.rspamd_log_id:
                db.query(RspamdLog).filter(
                    RspamdLog.id == primary.rspamd_log_id
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            # Delete the duplicates
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
    """
    Add indexes for Message-ID columns if they don't exist
    Critical for performance with the new Message-ID-based correlation
    """
    logger.info("Ensuring Message-ID indexes exist...")
    
    try:
        # Check and create index for PostfixLog.message_id
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_postfix_message_id 
            ON postfix_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        # Check and create index for RspamdLog.message_id  
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_rspamd_message_id 
            ON rspamd_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        # Check and create index for MessageCorrelation.message_id
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
    """
    Add is_complete column to message_correlations if it doesn't exist
    This tracks whether we've found all Postfix logs for a correlation
    """
    logger.info("Checking if is_complete column exists...")
    
    try:
        # Check if column exists
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='message_correlations' 
            AND column_name='is_complete'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding is_complete column...")
            
            # Add column
            db.execute(text("""
                ALTER TABLE message_correlations 
                ADD COLUMN is_complete BOOLEAN DEFAULT FALSE
            """))
            
            # Add index
            db.execute(text("""
                CREATE INDEX idx_correlation_is_complete 
                ON message_correlations (is_complete)
            """))
            
            # Mark existing correlations with Queue-ID as complete
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


def ensure_domain_dns_checks_table(db: Session):
    """Ensure domain_dns_checks table exists"""
    logger.info("Checking if domain_dns_checks table exists...")
    
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'domain_dns_checks'
            );
        """))
        
        table_exists = result.fetchone()[0]
        
        if table_exists:
            logger.info("domain_dns_checks table already exists")
            return
        
        logger.info("Creating domain_dns_checks table...")
        
        try:
            db.execute(text("""
                CREATE TABLE domain_dns_checks (
                    id SERIAL PRIMARY KEY,
                    domain_name VARCHAR(255) NOT NULL UNIQUE,
                    spf_check JSONB,
                    dkim_check JSONB,
                    dmarc_check JSONB,
                    checked_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            
            db.execute(text("""
                CREATE INDEX idx_domain_dns_checks_domain 
                ON domain_dns_checks(domain_name);
            """))
            
            db.execute(text("""
                CREATE INDEX idx_domain_dns_checks_checked_at 
                ON domain_dns_checks(checked_at);
            """))
            
            db.commit()
            logger.info("✓ domain_dns_checks table created successfully")
            
        except Exception as create_error:
            db.rollback()

            if "duplicate key value violates unique constraint" in str(create_error).lower():
                logger.warning("Detected PostgreSQL artifact, cleaning up...")
                
                try:
                    # Clean up ALL artifacts
                    db.execute(text("DROP SEQUENCE IF EXISTS domain_dns_checks_id_seq CASCADE;"))
                    db.execute(text("DROP TABLE IF EXISTS domain_dns_checks CASCADE;"))
                    db.execute(text("DROP TYPE IF EXISTS domain_dns_checks CASCADE;"))
                    db.commit()
                    logger.info("Cleaned up PostgreSQL artifacts")

                    # Retry
                    db.execute(text("""
                        CREATE TABLE domain_dns_checks (
                            id SERIAL PRIMARY KEY,
                            domain_name VARCHAR(255) NOT NULL UNIQUE,
                            spf_check JSONB,
                            dkim_check JSONB,
                            dmarc_check JSONB,
                            checked_at TIMESTAMP NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_domain_dns_checks_domain 
                        ON domain_dns_checks(domain_name);
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_domain_dns_checks_checked_at 
                        ON domain_dns_checks(checked_at);
                    """))
                    
                    db.commit()
                    logger.info("✓ domain_dns_checks table created after cleanup")
                    
                except Exception as retry_error:
                    logger.error(f"Failed after cleanup: {retry_error}")
                    db.rollback()
                    raise
            else:
                logger.error(f"Failed to create table: {create_error}")
                raise
        
    except Exception as e:
        logger.error(f"Error ensuring domain_dns_checks table: {e}")
        db.rollback()


def add_is_full_check_column(db: Session):
    """Add is_full_check column to domain_dns_checks"""
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
    """
    Add UNIQUE constraint to postfix_logs to prevent duplicate logs
    """
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

def ensure_dmarc_tables(db: Session):
    """Ensure DMARC tables exist with proper structure"""
    logger.info("Checking if DMARC tables exist...")
    
    try:
        # Check if dmarc_reports table exists
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'dmarc_reports'
            );
        """))
        
        reports_exists = result.fetchone()[0]
        
        # Check if dmarc_records table exists
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'dmarc_records'
            );
        """))
        
        records_exists = result.fetchone()[0]
        
        if reports_exists and records_exists:
            logger.info("DMARC tables already exist")
            return
        
        # If tables exist partially, clean up
        if reports_exists or records_exists:
            logger.warning("DMARC tables exist partially, cleaning up...")
            try:
                db.execute(text("DROP TABLE IF EXISTS dmarc_records CASCADE;"))
                db.execute(text("DROP TABLE IF EXISTS dmarc_reports CASCADE;"))
                db.execute(text("DROP SEQUENCE IF EXISTS dmarc_reports_id_seq CASCADE;"))
                db.execute(text("DROP SEQUENCE IF EXISTS dmarc_records_id_seq CASCADE;"))
                db.commit()
                logger.info("Cleaned up partial DMARC tables")
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {cleanup_error}")
                db.rollback()
                raise
        
        logger.info("Creating DMARC tables...")
        
        try:
            # Create dmarc_reports table
            db.execute(text("""
                CREATE TABLE dmarc_reports (
                    id SERIAL PRIMARY KEY,
                    report_id VARCHAR(255) NOT NULL UNIQUE,
                    domain VARCHAR(255) NOT NULL,
                    org_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    extra_contact_info TEXT,
                    begin_date INTEGER NOT NULL,
                    end_date INTEGER NOT NULL,
                    policy_published JSONB,
                    domain_id VARCHAR(255),
                    raw_xml TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            
            # Create indexes for dmarc_reports
            db.execute(text("""
                CREATE INDEX idx_dmarc_report_domain_date 
                ON dmarc_reports(domain, begin_date);
            """))
            
            db.execute(text("""
                CREATE INDEX idx_dmarc_report_org 
                ON dmarc_reports(org_name);
            """))
            
            db.execute(text("""
                CREATE INDEX idx_dmarc_report_created 
                ON dmarc_reports(created_at);
            """))
            
            # Create dmarc_records table
            db.execute(text("""
                CREATE TABLE dmarc_records (
                    id SERIAL PRIMARY KEY,
                    dmarc_report_id INTEGER NOT NULL,
                    source_ip VARCHAR(50) NOT NULL,
                    count INTEGER NOT NULL,
                    disposition VARCHAR(20),
                    dkim_result VARCHAR(20),
                    spf_result VARCHAR(20),
                    header_from VARCHAR(255),
                    envelope_from VARCHAR(255),
                    envelope_to VARCHAR(255),
                    auth_results JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            
            # Create indexes for dmarc_records
            db.execute(text("""
                CREATE INDEX idx_dmarc_record_report 
                ON dmarc_records(dmarc_report_id);
            """))
            
            db.execute(text("""
                CREATE INDEX idx_dmarc_record_ip 
                ON dmarc_records(source_ip);
            """))
            
            db.execute(text("""
                CREATE INDEX idx_dmarc_record_results 
                ON dmarc_records(dkim_result, spf_result);
            """))
            
            db.commit()
            logger.info("✓ DMARC tables created successfully")
            
        except Exception as create_error:
            db.rollback()
            
            # Handle duplicate key errors (PostgreSQL artifacts)
            if "duplicate key value violates unique constraint" in str(create_error).lower():
                logger.warning("Detected PostgreSQL artifacts, cleaning up...")
                
                try:
                    # Clean up ALL artifacts
                    db.execute(text("DROP TABLE IF EXISTS dmarc_records CASCADE;"))
                    db.execute(text("DROP TABLE IF EXISTS dmarc_reports CASCADE;"))
                    db.execute(text("DROP SEQUENCE IF EXISTS dmarc_reports_id_seq CASCADE;"))
                    db.execute(text("DROP SEQUENCE IF EXISTS dmarc_records_id_seq CASCADE;"))
                    db.commit()
                    logger.info("Cleaned up PostgreSQL artifacts")
                    
                    # Retry - create tables again
                    db.execute(text("""
                        CREATE TABLE dmarc_reports (
                            id SERIAL PRIMARY KEY,
                            report_id VARCHAR(255) NOT NULL UNIQUE,
                            domain VARCHAR(255) NOT NULL,
                            org_name VARCHAR(255) NOT NULL,
                            email VARCHAR(255),
                            extra_contact_info TEXT,
                            begin_date INTEGER NOT NULL,
                            end_date INTEGER NOT NULL,
                            policy_published JSONB,
                            domain_id VARCHAR(255),
                            raw_xml TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_report_domain_date 
                        ON dmarc_reports(domain, begin_date);
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_report_org 
                        ON dmarc_reports(org_name);
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_report_created 
                        ON dmarc_reports(created_at);
                    """))
                    
                    db.execute(text("""
                        CREATE TABLE dmarc_records (
                            id SERIAL PRIMARY KEY,
                            dmarc_report_id INTEGER NOT NULL,
                            source_ip VARCHAR(50) NOT NULL,
                            count INTEGER NOT NULL,
                            disposition VARCHAR(20),
                            dkim_result VARCHAR(20),
                            spf_result VARCHAR(20),
                            header_from VARCHAR(255),
                            envelope_from VARCHAR(255),
                            envelope_to VARCHAR(255),
                            auth_results JSONB,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_record_report 
                        ON dmarc_records(dmarc_report_id);
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_record_ip 
                        ON dmarc_records(source_ip);
                    """))
                    
                    db.execute(text("""
                        CREATE INDEX idx_dmarc_record_results 
                        ON dmarc_records(dkim_result, spf_result);
                    """))
                    
                    db.commit()
                    logger.info("✓ DMARC tables created after cleanup")
                    
                except Exception as retry_error:
                    logger.error(f"Failed after cleanup: {retry_error}")
                    db.rollback()
                    raise
            else:
                logger.error(f"Failed to create DMARC tables: {create_error}")
                raise
        
    except Exception as e:
        logger.error(f"Error ensuring DMARC tables: {e}")
        db.rollback()
        raise

def add_geoip_fields_to_dmarc(db: Session):
    """Add GeoIP fields to dmarc_records table"""
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
    """Add GeoIP fields to rspamd_logs table"""
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

def create_dmarc_sync_table(db: Session):
    """
    Create dmarc_syncs table for tracking IMAP sync operations
    This table tracks automatic and manual DMARC report imports from IMAP
    """
    logger.info("Checking if dmarc_syncs table exists...")
    
    try:
        # Check if table already exists
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
        
        # Create table
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
        
        # Create indexes
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
    """Ensure mailbox_statistics table exists with proper structure"""
    try:
        # Check if table exists
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
            
            # Create indexes
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


def run_migrations():
    """
    Run all database migrations and maintenance tasks
    Called during application startup
    """
    logger.info("Running database migrations...")
    
    db = SessionLocal()
    try:
        # Ensure Message-ID indexes exist (critical for performance)
        add_message_id_indexes(db)
        
        # Add is_complete column if missing (for tracking correlation completion)
        add_is_complete_column(db)
        
        # Domain DNS table
        ensure_domain_dns_checks_table(db)
        add_is_full_check_column(db)

        # UNIQUE postfix logs
        add_postfix_unique_constraint(db)

        # Clean up duplicate correlations
        removed = cleanup_duplicate_correlations(db)

        # DMARC table
        ensure_dmarc_tables(db)
        create_dmarc_sync_table(db)

        # GeoIP fields
        add_geoip_fields_to_dmarc(db)
        
        # Mailbox statistics table
        ensure_mailbox_statistics_table(db)
        
        # Alias statistics table
        ensure_alias_statistics_table(db)

        # System settings (for cache signaling)
        ensure_system_settings_table(db)
        
        add_geoip_fields_to_dmarc(db)
        add_geoip_fields_to_rspamd(db)
        
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
    """Ensure alias_statistics table exists with all required fields"""
    try:
        # Check if table exists
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
            
            # Create indexes
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
    """Ensure system_settings table exists"""
    try:
        # Check if table exists
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
