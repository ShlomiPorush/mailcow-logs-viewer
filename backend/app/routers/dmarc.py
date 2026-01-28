"""
DMARC Router - Domain-centric view (Cloudflare style)
"""
import logging
import hashlib
import json
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, case

from ..database import get_db
from ..models import DMARCReport, DMARCRecord, DMARCSync, TLSReport, TLSReportPolicy
from ..services.dmarc_parser import parse_dmarc_file
from ..services.geoip_service import enrich_dmarc_record
from ..services.dmarc_imap_service import sync_dmarc_reports_from_imap
from ..services.dmarc_cache import (
    get_dmarc_cache_key, 
    get_dmarc_cached, 
    set_dmarc_cache, 
    clear_dmarc_cache
)
from ..config import settings
from ..scheduler import update_job_status

logger = logging.getLogger(__name__)

router = APIRouter()

# =============================================================================
# DOMAINS LIST
# =============================================================================

@router.post("/dmarc/cache/clear")
async def clear_cache(
    db: Session = Depends(get_db)
):
    """
    Clear all DMARC related cache
    """
    try:
        clear_dmarc_cache(db)
        return {"status": "success", "message": "Cache cleared"}
    except Exception as e:
        logger.error(f"Error clearing DMARC cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# REPORTS MANAGEMENT
# =============================================================================

@router.get("/dmarc/reports/config")
async def get_reports_management_config():
    """
    Get reports management configuration
    """
    return {
        "allow_delete": settings.dmarc_allow_report_delete
    }


@router.get("/dmarc/reports/all")
async def get_all_reports(
    db: Session = Depends(get_db)
):
    """
    Get all DMARC and TLS reports for management view
    """
    try:
        reports = []
        
        # Get DMARC reports
        dmarc_reports = db.query(DMARCReport).order_by(DMARCReport.created_at.desc()).all()
        
        for report in dmarc_reports:
            # Count records for this report
            record_count = db.query(func.count(DMARCRecord.id)).filter(
                DMARCRecord.dmarc_report_id == report.id
            ).scalar() or 0
            
            reports.append({
                "id": report.id,
                "type": "dmarc",
                "domain": report.domain,
                "org_name": report.org_name,
                "begin_date": report.begin_date,
                "end_date": report.end_date,
                "record_count": record_count,
                "created_at": report.created_at.isoformat() if report.created_at else None,
                "report_id": report.report_id
            })
        
        # Get TLS reports
        tls_reports = db.query(TLSReport).order_by(TLSReport.created_at.desc()).all()
        
        for report in tls_reports:
            # Count policies for this report
            policy_count = db.query(func.count(TLSReportPolicy.id)).filter(
                TLSReportPolicy.tls_report_id == report.id
            ).scalar() or 0
            
            reports.append({
                "id": report.id,
                "type": "tls",
                "domain": report.policy_domain,
                "org_name": report.organization_name,
                "begin_date": int(report.start_datetime.timestamp()) if report.start_datetime else None,
                "end_date": int(report.end_datetime.timestamp()) if report.end_datetime else None,
                "record_count": policy_count,
                "created_at": report.created_at.isoformat() if report.created_at else None,
                "report_id": report.report_id
            })
        
        # Sort all reports by created_at (newest first)
        reports.sort(key=lambda x: x["created_at"] or "", reverse=True)
        
        return {
            "reports": reports,
            "total": len(reports),
            "allow_delete": settings.dmarc_allow_report_delete
        }
        
    except Exception as e:
        logger.error(f"Error fetching all reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/dmarc/reports/{report_type}/{report_id}")
async def delete_report(
    report_type: str,
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a specific DMARC or TLS report
    """
    # Check if deletion is allowed
    if not settings.dmarc_allow_report_delete:
        raise HTTPException(
            status_code=403, 
            detail="Report deletion is disabled. Set DMARC_ALLOW_REPORT_DELETE=true to enable."
        )
    
    try:
        if report_type == "dmarc":
            # Delete associated records first
            db.query(DMARCRecord).filter(
                DMARCRecord.dmarc_report_id == report_id
            ).delete()
            
            # Delete the report
            result = db.query(DMARCReport).filter(DMARCReport.id == report_id).delete()
            
            if result == 0:
                raise HTTPException(status_code=404, detail="Report not found")
                
        elif report_type == "tls":
            # Delete associated policies first
            db.query(TLSReportPolicy).filter(
                TLSReportPolicy.tls_report_id == report_id
            ).delete()
            
            # Delete the report
            result = db.query(TLSReport).filter(TLSReport.id == report_id).delete()
            
            if result == 0:
                raise HTTPException(status_code=404, detail="Report not found")
        else:
            raise HTTPException(status_code=400, detail="Invalid report type. Use 'dmarc' or 'tls'.")
        
        db.commit()
        
        # Clear cache
        clear_dmarc_cache(db)
        
        return {"status": "success", "message": f"{report_type.upper()} report deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dmarc/domains")
async def get_domains_list(
    db: Session = Depends(get_db)
):
    """
    Get list of all domains with DMARC and/or TLS-RPT reports and their statistics
    """
    try:
        # Check cache first
        cache_key = get_dmarc_cache_key("domains_list")
        cached_result = get_dmarc_cached(cache_key, db)
        if cached_result is not None:
            return cached_result
        
        # Get domains from DMARC reports
        dmarc_domains = db.query(
            DMARCReport.domain,
            func.count(DMARCReport.id).label('report_count'),
            func.min(DMARCReport.begin_date).label('first_report'),
            func.max(DMARCReport.end_date).label('last_report')
        ).group_by(
            DMARCReport.domain
        ).all()
        
        # Get domains from TLS reports
        tls_domains = db.query(
            TLSReport.policy_domain
        ).distinct().all()
        tls_domain_set = {d[0] for d in tls_domains}
        
        # Combine domains
        all_domains = set()
        dmarc_domain_data = {}
        
        for domain, report_count, first_report, last_report in dmarc_domains:
            all_domains.add(domain)
            dmarc_domain_data[domain] = {
                'report_count': report_count,
                'first_report': first_report,
                'last_report': last_report
            }
        
        # Add TLS-only domains
        all_domains.update(tls_domain_set)
        
        domains_list = []
        
        for domain in all_domains:
            thirty_days_ago = int((datetime.now() - timedelta(days=30)).timestamp())
            thirty_days_ago_datetime = datetime.now() - timedelta(days=30)
            
            # Get TLS stats for this domain
            tls_stats = db.query(
                func.count(TLSReport.id).label('tls_report_count'),
                func.sum(TLSReportPolicy.successful_session_count).label('tls_success'),
                func.sum(TLSReportPolicy.failed_session_count).label('tls_fail')
            ).join(
                TLSReportPolicy,
                TLSReportPolicy.tls_report_id == TLSReport.id
            ).filter(
                and_(
                    TLSReport.policy_domain == domain,
                    TLSReport.start_datetime >= thirty_days_ago_datetime
                )
            ).first()
            
            tls_report_count = tls_stats.tls_report_count or 0
            tls_success = tls_stats.tls_success or 0
            tls_fail = tls_stats.tls_fail or 0
            tls_total = tls_success + tls_fail
            tls_success_pct = round((tls_success / tls_total * 100) if tls_total > 0 else 100, 2)
            
            # Get DMARC stats
            dmarc_data = dmarc_domain_data.get(domain)
            if dmarc_data:
                stats = db.query(
                    func.sum(DMARCRecord.count).label('total_messages'),
                    func.count(func.distinct(DMARCRecord.source_ip)).label('unique_ips'),
                    func.sum(
                        case(
                            (and_(DMARCRecord.spf_result == 'pass', DMARCRecord.dkim_result == 'pass'), DMARCRecord.count),
                            else_=0
                        )
                    ).label('dmarc_pass_count')
                ).join(
                    DMARCReport,
                    DMARCRecord.dmarc_report_id == DMARCReport.id
                ).filter(
                    and_(
                        DMARCReport.domain == domain,
                        DMARCReport.begin_date >= thirty_days_ago
                    )
                ).first()
                
                total_msgs = stats.total_messages or 0
                dmarc_pass = stats.dmarc_pass_count or 0
                
                domains_list.append({
                    'domain': domain,
                    'report_count': dmarc_data['report_count'],
                    'tls_report_count': tls_report_count,
                    'first_report': dmarc_data['first_report'],
                    'last_report': dmarc_data['last_report'],
                    'has_dmarc': True,
                    'has_tls': domain in tls_domain_set,
                    'stats_30d': {
                        'total_messages': total_msgs,
                        'unique_ips': stats.unique_ips or 0,
                        'dmarc_pass_pct': round((dmarc_pass / total_msgs * 100) if total_msgs > 0 else 0, 2),
                        'tls_success_pct': tls_success_pct
                    }
                })
            else:
                # TLS-only domain
                tls_report = db.query(TLSReport).filter(
                    TLSReport.policy_domain == domain
                ).order_by(TLSReport.end_datetime.desc()).first()
                
                first_tls = db.query(func.min(TLSReport.start_datetime)).filter(
                    TLSReport.policy_domain == domain
                ).scalar()
                
                domains_list.append({
                    'domain': domain,
                    'report_count': 0,
                    'tls_report_count': tls_report_count,
                    'first_report': int(first_tls.timestamp()) if first_tls else None,
                    'last_report': int(tls_report.end_datetime.timestamp()) if tls_report and tls_report.end_datetime else None,
                    'has_dmarc': False,
                    'has_tls': True,
                    'stats_30d': {
                        'total_messages': 0,
                        'unique_ips': 0,
                        'dmarc_pass_pct': 0,
                        'tls_success_pct': tls_success_pct
                    }
                })
        
        # Sort by last_report, handling None values
        domains_list.sort(key=lambda x: x['last_report'] or 0, reverse=True)
        
        response = {
            'domains': domains_list,
            'total': len(domains_list)
        }
        
        # Cache the result
        set_dmarc_cache(cache_key, response)
        
        return response
        
    except Exception as e:
        logger.error(f"Error fetching domains list: {e}")
        raise HTTPException(status_code=500, detail=str(e))



# =============================================================================
# DOMAIN OVERVIEW
# =============================================================================

@router.get("/dmarc/domains/{domain}/overview")
async def get_domain_overview(
    domain: str,
    days: int = 30,
    db: Session = Depends(get_db)
):
    """
    Get overview for specific domain with daily aggregated stats
    Includes data for charts similar to Cloudflare
    """
    try:
        cutoff_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())
        
        reports = db.query(DMARCReport).filter(
            and_(
                DMARCReport.domain == domain,
                DMARCReport.begin_date >= cutoff_timestamp
            )
        ).all()
        
        if not reports:
            return {
                'domain': domain,
                'policy': None,
                'daily_stats': [],
                'totals': {
                    'total_messages': 0,
                    'dmarc_pass': 0,
                    'dmarc_fail': 0,
                    'unique_ips': 0,
                    'unique_reporters': 0
                }
            }
        
        latest_report = max(reports, key=lambda r: r.end_date)
        policy = latest_report.policy_published or {}
        
        daily_data = {}
        all_ips = set()
        all_reporters = set()
        
        for report in reports:
            report_date = datetime.fromtimestamp(report.begin_date).date().isoformat()
            
            if report_date not in daily_data:
                daily_data[report_date] = {
                    'date': report_date,
                    'total': 0,
                    'dmarc_pass': 0,
                    'dmarc_fail': 0,
                    'spf_pass': 0,
                    'dkim_pass': 0
                }
            
            all_reporters.add(report.org_name)
            
            records = db.query(DMARCRecord).filter(
                DMARCRecord.dmarc_report_id == report.id
            ).all()
            
            for record in records:
                all_ips.add(record.source_ip)
                
                daily_data[report_date]['total'] += record.count
                
                if record.spf_result == 'pass' and record.dkim_result == 'pass':
                    daily_data[report_date]['dmarc_pass'] += record.count
                else:
                    daily_data[report_date]['dmarc_fail'] += record.count
                
                if record.spf_result == 'pass':
                    daily_data[report_date]['spf_pass'] += record.count
                
                if record.dkim_result == 'pass':
                    daily_data[report_date]['dkim_pass'] += record.count
        
        daily_stats = sorted(daily_data.values(), key=lambda x: x['date'])
        
        total_messages = sum(d['total'] for d in daily_stats)
        total_dmarc_pass = sum(d['dmarc_pass'] for d in daily_stats)
        total_dmarc_fail = sum(d['dmarc_fail'] for d in daily_stats)
        
        return {
            'domain': domain,
            'policy': {
                'p': policy.get('p', 'none'),
                'sp': policy.get('sp'),
                'pct': policy.get('pct', 100),
                'adkim': policy.get('adkim', 'r'),
                'aspf': policy.get('aspf', 'r')
            },
            'daily_stats': daily_stats,
            'totals': {
                'total_messages': total_messages,
                'dmarc_pass': total_dmarc_pass,
                'dmarc_pass_pct': round((total_dmarc_pass / total_messages * 100) if total_messages > 0 else 0, 2),
                'dmarc_fail': total_dmarc_fail,
                'unique_ips': len(all_ips),
                'unique_reporters': len(all_reporters)
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching domain overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# DOMAIN REPORTS (by day)
# =============================================================================

@router.get("/dmarc/domains/{domain}/reports")
async def get_domain_reports(
    domain: str,
    days: int = 30,
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get daily aggregated reports for a domain
    Groups multiple reports from same day together
    """
    try:
        cutoff_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())
        
        reports = db.query(DMARCReport).filter(
            and_(
                DMARCReport.domain == domain,
                DMARCReport.begin_date >= cutoff_timestamp
            )
        ).all()
        
        daily_reports = {}
        
        for report in reports:
            report_date = datetime.fromtimestamp(report.begin_date).date().isoformat()
            
            if report_date not in daily_reports:
                daily_reports[report_date] = {
                    'date': report_date,
                    'total_messages': 0,
                    'dmarc_pass': 0,
                    'spf_pass': 0,
                    'dkim_pass': 0,
                    'unique_ips': set(),
                    'reporters': set(),
                    'reports': []
                }
            
            records = db.query(DMARCRecord).filter(
                DMARCRecord.dmarc_report_id == report.id
            ).all()
            
            total_for_report = sum(r.count for r in records)
            dmarc_pass_for_report = sum(r.count for r in records if r.spf_result == 'pass' and r.dkim_result == 'pass')
            spf_pass_for_report = sum(r.count for r in records if r.spf_result == 'pass')
            dkim_pass_for_report = sum(r.count for r in records if r.dkim_result == 'pass')
            
            daily_reports[report_date]['reports'].append({
                'report_id': report.report_id,
                'org_name': report.org_name,
                'begin_date': report.begin_date,
                'end_date': report.end_date,
                'volume': total_for_report,
                'dmarc_pass_pct': round((dmarc_pass_for_report / total_for_report * 100) if total_for_report > 0 else 0, 2)
            })
            
            daily_reports[report_date]['total_messages'] += total_for_report
            daily_reports[report_date]['dmarc_pass'] += dmarc_pass_for_report
            daily_reports[report_date]['spf_pass'] += spf_pass_for_report
            daily_reports[report_date]['dkim_pass'] += dkim_pass_for_report
            daily_reports[report_date]['reporters'].add(report.org_name)
            
            for record in records:
                daily_reports[report_date]['unique_ips'].add(record.source_ip)
        
        daily_list = []
        for date, data in daily_reports.items():
            total = data['total_messages']
            daily_list.append({
                'date': date,
                'total_messages': total,
                'dmarc_pass_pct': round((data['dmarc_pass'] / total * 100) if total > 0 else 0, 2),
                'spf_pass_pct': round((data['spf_pass'] / total * 100) if total > 0 else 0, 2),
                'dkim_pass_pct': round((data['dkim_pass'] / total * 100) if total > 0 else 0, 2),
                'unique_ips': len(data['unique_ips']),
                'reporters': list(data['reporters']),
                'reports': data['reports']
            })
        
        daily_list.sort(key=lambda x: x['date'], reverse=True)
        
        total = len(daily_list)
        start = (page - 1) * limit
        end = start + limit
        
        return {
            'domain': domain,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit if total > 0 else 0,
            'data': daily_list[start:end]
        }
        
    except Exception as e:
        logger.error(f"Error fetching domain reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# REPORT DETAILS (specific date)
# =============================================================================

@router.get("/dmarc/domains/{domain}/reports/{report_date}/details")
async def get_report_details(
    domain: str,
    report_date: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed information for a specific report date
    Shows all sources (IPs) that sent emails on that day
    """
    try:
        date_obj = datetime.strptime(report_date, '%Y-%m-%d').date()
        start_timestamp = int(datetime.combine(date_obj, datetime.min.time()).timestamp())
        end_timestamp = int(datetime.combine(date_obj, datetime.max.time()).timestamp())
        
        reports = db.query(DMARCReport).filter(
            and_(
                DMARCReport.domain == domain,
                DMARCReport.begin_date >= start_timestamp,
                DMARCReport.begin_date <= end_timestamp
            )
        ).all()
        
        if not reports:
            raise HTTPException(status_code=404, detail="Report not found")
        
        sources = {}
        total_messages = 0
        dmarc_pass_count = 0
        spf_pass_count = 0
        dkim_pass_count = 0
        reporters = set()
        
        for report in reports:
            reporters.add(report.org_name)
            
            records = db.query(DMARCRecord).filter(
                DMARCRecord.dmarc_report_id == report.id
            ).all()
            
            for record in records:
                ip = record.source_ip
                
                if ip not in sources:
                    source_data = enrich_dmarc_record({'source_ip': ip})
                    sources[ip] = {
                        'source_ip': ip,
                        'source_name': source_data.get('asn_org', 'Unknown'),
                        'country_code': source_data.get('country_code'),
                        'country_name': source_data.get('country_name'),
                        'city': source_data.get('city'),
                        'asn': source_data.get('asn'),
                        'asn_org': source_data.get('asn_org'),
                        'header_from': record.header_from,
                        'envelope_from': record.envelope_from,
                        'reporter': report.org_name,
                        'volume': 0,
                        'dmarc_pass': 0,
                        'dmarc_fail': 0,
                        'spf_pass': 0,
                        'dkim_pass': 0
                    }
                
                sources[ip]['volume'] += record.count
                total_messages += record.count
                
                if record.spf_result == 'pass' and record.dkim_result == 'pass':
                    sources[ip]['dmarc_pass'] += record.count
                    dmarc_pass_count += record.count
                else:
                    sources[ip]['dmarc_fail'] += record.count
                
                if record.spf_result == 'pass':
                    sources[ip]['spf_pass'] += record.count
                    spf_pass_count += record.count
                
                if record.dkim_result == 'pass':
                    sources[ip]['dkim_pass'] += record.count
                    dkim_pass_count += record.count
        
        sources_list = []
        for source_data in sources.values():
            volume = source_data['volume']
            sources_list.append({
                **source_data,
                'dmarc_pass_pct': round((source_data['dmarc_pass'] / volume * 100) if volume > 0 else 0, 2),
                'spf_pass_pct': round((source_data['spf_pass'] / volume * 100) if volume > 0 else 0, 2),
                'dkim_pass_pct': round((source_data['dkim_pass'] / volume * 100) if volume > 0 else 0, 2)
            })
        
        sources_list.sort(key=lambda x: x['volume'], reverse=True)
        
        return {
            'domain': domain,
            'date': report_date,
            'totals': {
                'total_messages': total_messages,
                'dmarc_pass': dmarc_pass_count,
                'dmarc_pass_pct': round((dmarc_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'spf_pass': spf_pass_count,
                'spf_pass_pct': round((spf_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'dkim_pass': dkim_pass_count,
                'dkim_pass_pct': round((dkim_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'unique_ips': len(sources_list),
                'reporters': list(reporters)
            },
            'sources': sources_list
        }
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    except Exception as e:
        logger.error(f"Error fetching report details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# DOMAIN SOURCES
# =============================================================================

@router.get("/dmarc/domains/{domain}/sources")
async def get_domain_sources(
    domain: str,
    days: int = 30,
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get aggregated sources (IPs) for a domain
    With GeoIP enrichment
    """
    try:
        cutoff_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())
        
        records_query = db.query(
            DMARCRecord.source_ip,
            func.sum(DMARCRecord.count).label('total_count'),
            func.sum(
                case(
                    (and_(DMARCRecord.spf_result == 'pass', DMARCRecord.dkim_result == 'pass'), DMARCRecord.count),
                    else_=0
                )
            ).label('dmarc_pass_count'),
            func.sum(
                case(
                    (DMARCRecord.spf_result == 'pass', DMARCRecord.count),
                    else_=0
                )
            ).label('spf_pass_count'),
            func.sum(
                case(
                    (DMARCRecord.dkim_result == 'pass', DMARCRecord.count),
                    else_=0
                )
            ).label('dkim_pass_count')
        ).join(
            DMARCReport,
            DMARCRecord.dmarc_report_id == DMARCReport.id
        ).filter(
            and_(
                DMARCReport.domain == domain,
                DMARCReport.begin_date >= cutoff_timestamp
            )
        ).group_by(
            DMARCRecord.source_ip
        ).order_by(
            func.sum(DMARCRecord.count).desc()
        ).all()
        
        sources_list = []
        for ip, total, dmarc_pass, spf_pass, dkim_pass in records_query:
            source_data = enrich_dmarc_record({'source_ip': ip})
            
            sources_list.append({
                'source_ip': ip,
                'country_code': source_data.get('country_code'),
                'country_name': source_data.get('country_name'),
                'country_emoji': source_data.get('country_emoji', '🌍'),
                'city': source_data.get('city'),
                'asn': source_data.get('asn'),
                'asn_org': source_data.get('asn_org'),
                'total_count': total,
                'dmarc_pass': dmarc_pass,
                'dmarc_pass_pct': round((dmarc_pass / total * 100) if total > 0 else 0, 2),
                'spf_pass': spf_pass,
                'spf_pass_pct': round((spf_pass / total * 100) if total > 0 else 0, 2),
                'dkim_pass': dkim_pass,
                'dkim_pass_pct': round((dkim_pass / total * 100) if total > 0 else 0, 2)
            })
        
        total = len(sources_list)
        start = (page - 1) * limit
        end = start + limit
        
        return {
            'domain': domain,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit if total > 0 else 0,
            'data': sources_list[start:end]
        }
        
    except Exception as e:
        logger.error(f"Error fetching domain sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# SOURCE DETAILS (specific IP aggregated across dates)
# =============================================================================

@router.get("/dmarc/domains/{domain}/sources/{source_ip}/details")
async def get_source_details(
    domain: str,
    source_ip: str,
    days: int = 30,
    db: Session = Depends(get_db)
):
    """
    Get detailed information for a specific source IP
    Shows all dates when this IP sent emails, grouped by envelope_from
    """
    try:
        cutoff_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())
        
        records = db.query(DMARCRecord, DMARCReport).join(
            DMARCReport,
            DMARCRecord.dmarc_report_id == DMARCReport.id
        ).filter(
            and_(
                DMARCReport.domain == domain,
                DMARCRecord.source_ip == source_ip,
                DMARCReport.begin_date >= cutoff_timestamp
            )
        ).all()
        
        if not records:
            raise HTTPException(status_code=404, detail="Source not found")
        
        source_data = enrich_dmarc_record({'source_ip': source_ip})
        
        envelope_from_groups = {}
        total_messages = 0
        dmarc_pass_count = 0
        spf_pass_count = 0
        dkim_pass_count = 0
        reporters = set()
        
        for record, report in records:
            envelope = record.envelope_from
            reporters.add(report.org_name)
            
            if envelope not in envelope_from_groups:
                envelope_from_groups[envelope] = {
                    'envelope_from': envelope,
                    'header_from': record.header_from,
                    'reporter': report.org_name,
                    'volume': 0,
                    'dmarc_pass': 0,
                    'dmarc_fail': 0,
                    'spf_aligned': 0,
                    'dkim_aligned': 0,
                    'spf_result': record.spf_result,
                    'dkim_result': record.dkim_result
                }
            
            envelope_from_groups[envelope]['volume'] += record.count
            total_messages += record.count
            
            if record.spf_result == 'pass' and record.dkim_result == 'pass':
                envelope_from_groups[envelope]['dmarc_pass'] += record.count
                dmarc_pass_count += record.count
            else:
                envelope_from_groups[envelope]['dmarc_fail'] += record.count
            
            if record.spf_result == 'pass':
                envelope_from_groups[envelope]['spf_aligned'] += record.count
                spf_pass_count += record.count
            
            if record.dkim_result == 'pass':
                envelope_from_groups[envelope]['dkim_aligned'] += record.count
                dkim_pass_count += record.count
        
        envelope_list = sorted(envelope_from_groups.values(), key=lambda x: x['volume'], reverse=True)
        
        return {
            'domain': domain,
            'source_ip': source_ip,
            'source_name': source_data.get('asn_org', 'Unknown'),
            'country_code': source_data.get('country_code'),
            'country_name': source_data.get('country_name'),
            'city': source_data.get('city'),
            'asn': source_data.get('asn'),
            'asn_org': source_data.get('asn_org'),
            'totals': {
                'total_messages': total_messages,
                'dmarc_pass': dmarc_pass_count,
                'dmarc_pass_pct': round((dmarc_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'spf_pass': spf_pass_count,
                'spf_pass_pct': round((spf_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'dkim_pass': dkim_pass_count,
                'dkim_pass_pct': round((dkim_pass_count / total_messages * 100) if total_messages > 0 else 0, 2),
                'unique_envelopes': len(envelope_list),
                'reporters': list(reporters)
            },
            'envelope_from_groups': envelope_list
        }
        
    except Exception as e:
        logger.error(f"Error fetching source details: {e}")
        raise HTTPException(status_code=500, detail=str(e))
# =============================================================================
# TLS-RPT REPORTS
# =============================================================================

@router.get("/dmarc/domains/{domain}/tls-reports")
async def get_domain_tls_reports(
    domain: str,
    days: int = 30,
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get TLS-RPT reports for a domain
    Returns list of TLS reports with organization, date range, success/fail counts
    """
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Query TLS reports for domain
        reports_query = db.query(TLSReport).filter(
            and_(
                TLSReport.policy_domain == domain,
                TLSReport.start_datetime >= cutoff_date
            )
        ).order_by(TLSReport.start_datetime.desc())
        
        total = reports_query.count()
        reports = reports_query.offset((page - 1) * limit).limit(limit).all()
        
        # Get aggregated totals
        total_success = 0
        total_fail = 0
        organizations = set()
        
        reports_list = []
        for report in reports:
            # Get policies for this report
            policies = db.query(TLSReportPolicy).filter(
                TLSReportPolicy.tls_report_id == report.id
            ).all()
            
            report_success = sum(p.successful_session_count for p in policies)
            report_fail = sum(p.failed_session_count for p in policies)
            
            total_success += report_success
            total_fail += report_fail
            organizations.add(report.organization_name)
            
            policies_list = [{
                'policy_type': p.policy_type,
                'policy_domain': p.policy_domain,
                'mx_host': p.mx_host,
                'successful_sessions': p.successful_session_count,
                'failed_sessions': p.failed_session_count,
                'failure_details': p.failure_details
            } for p in policies]
            
            reports_list.append({
                'id': report.id,
                'report_id': report.report_id,
                'organization_name': report.organization_name,
                'contact_info': report.contact_info,
                'start_datetime': report.start_datetime.isoformat() if report.start_datetime else None,
                'end_datetime': report.end_datetime.isoformat() if report.end_datetime else None,
                'successful_sessions': report_success,
                'failed_sessions': report_fail,
                'total_sessions': report_success + report_fail,
                'success_rate': round((report_success / (report_success + report_fail) * 100) if (report_success + report_fail) > 0 else 100, 2),
                'policies': policies_list
            })
        
        return {
            'domain': domain,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit if total > 0 else 0,
            'totals': {
                'total_reports': total,
                'total_successful_sessions': total_success,
                'total_failed_sessions': total_fail,
                'overall_success_rate': round((total_success / (total_success + total_fail) * 100) if (total_success + total_fail) > 0 else 100, 2),
                'unique_organizations': len(organizations)
            },
            'data': reports_list
        }
        
    except Exception as e:
        logger.error(f"Error fetching TLS reports for domain {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dmarc/domains/{domain}/tls-reports/daily")
async def get_domain_tls_daily_reports(
    domain: str,
    days: int = 30,
    page: int = 1,
    limit: int = 30,
    db: Session = Depends(get_db)
):
    """
    Get TLS-RPT reports aggregated by date
    Groups multiple reports from same day together, like DMARC daily reports
    """
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Query all TLS reports for domain
        reports = db.query(TLSReport).filter(
            and_(
                TLSReport.policy_domain == domain,
                TLSReport.start_datetime >= cutoff_date
            )
        ).order_by(TLSReport.start_datetime.desc()).all()
        
        # Group by date
        daily_data = {}
        for report in reports:
            if report.start_datetime:
                date_key = report.start_datetime.strftime('%Y-%m-%d')
                if date_key not in daily_data:
                    daily_data[date_key] = {
                        'date': date_key,
                        'report_count': 0,
                        'organizations': set(),
                        'total_success': 0,
                        'total_fail': 0,
                        'reports': []
                    }
                
                # Get policies for this report
                policies = db.query(TLSReportPolicy).filter(
                    TLSReportPolicy.tls_report_id == report.id
                ).all()
                
                report_success = sum(p.successful_session_count for p in policies)
                report_fail = sum(p.failed_session_count for p in policies)
                
                daily_data[date_key]['report_count'] += 1
                daily_data[date_key]['organizations'].add(report.organization_name)
                daily_data[date_key]['total_success'] += report_success
                daily_data[date_key]['total_fail'] += report_fail
                daily_data[date_key]['reports'].append({
                    'id': report.id,
                    'organization_name': report.organization_name,
                    'successful_sessions': report_success,
                    'failed_sessions': report_fail
                })
        
        # Convert to list and add success rate
        daily_list = []
        for date_key in sorted(daily_data.keys(), reverse=True):
            data = daily_data[date_key]
            total = data['total_success'] + data['total_fail']
            success_rate = round((data['total_success'] / total * 100) if total > 0 else 100, 2)
            
            daily_list.append({
                'date': date_key,
                'report_count': data['report_count'],
                'organizations': list(data['organizations']),
                'organization_count': len(data['organizations']),
                'total_success': data['total_success'],
                'total_fail': data['total_fail'],
                'total_sessions': total,
                'success_rate': success_rate,
                'reports': data['reports']
            })
        
        # Pagination
        total = len(daily_list)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated = daily_list[start_idx:end_idx]
        
        # Calculate overall totals
        overall_success = sum(d['total_success'] for d in daily_list)
        overall_fail = sum(d['total_fail'] for d in daily_list)
        overall_total = overall_success + overall_fail
        
        return {
            'domain': domain,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit if total > 0 else 0,
            'totals': {
                'total_days': total,
                'total_reports': sum(d['report_count'] for d in daily_list),
                'total_successful_sessions': overall_success,
                'total_failed_sessions': overall_fail,
                'overall_success_rate': round((overall_success / overall_total * 100) if overall_total > 0 else 100, 2)
            },
            'data': paginated
        }
        
    except Exception as e:
        logger.error(f"Error fetching TLS daily reports for domain {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dmarc/domains/{domain}/tls-reports/{report_date}/details")
async def get_tls_report_details(
    domain: str,
    report_date: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed TLS-RPT reports for a specific date
    Shows all reports and policies from that day with breakdown by provider
    """
    try:
        date_obj = datetime.strptime(report_date, '%Y-%m-%d').date()
        start_dt = datetime.combine(date_obj, datetime.min.time(), tzinfo=timezone.utc)
        end_dt = datetime.combine(date_obj, datetime.max.time(), tzinfo=timezone.utc)
        
        reports = db.query(TLSReport).filter(
            and_(
                TLSReport.policy_domain == domain,
                TLSReport.start_datetime >= start_dt,
                TLSReport.start_datetime <= end_dt
            )
        ).all()
        
        if not reports:
            raise HTTPException(status_code=404, detail="No TLS reports found for this date")
        
        # Aggregate stats
        total_success = 0
        total_fail = 0
        providers = []
        
        for report in reports:
            policies = db.query(TLSReportPolicy).filter(
                TLSReportPolicy.tls_report_id == report.id
            ).all()
            
            report_success = sum(p.successful_session_count for p in policies)
            report_fail = sum(p.failed_session_count for p in policies)
            
            total_success += report_success
            total_fail += report_fail
            
            # Add provider details
            policies_list = []
            for p in policies:
                policies_list.append({
                    'policy_type': p.policy_type,
                    'policy_domain': p.policy_domain,
                    'mx_host': p.mx_host,
                    'successful_sessions': p.successful_session_count,
                    'failed_sessions': p.failed_session_count,
                    'total_sessions': p.successful_session_count + p.failed_session_count,
                    'success_rate': round((p.successful_session_count / (p.successful_session_count + p.failed_session_count) * 100) if (p.successful_session_count + p.failed_session_count) > 0 else 100, 2),
                    'failure_details': p.failure_details
                })
            
            providers.append({
                'report_id': report.report_id,
                'organization_name': report.organization_name,
                'contact_info': report.contact_info,
                'start_datetime': report.start_datetime.isoformat() if report.start_datetime else None,
                'end_datetime': report.end_datetime.isoformat() if report.end_datetime else None,
                'successful_sessions': report_success,
                'failed_sessions': report_fail,
                'total_sessions': report_success + report_fail,
                'success_rate': round((report_success / (report_success + report_fail) * 100) if (report_success + report_fail) > 0 else 100, 2),
                'policies': policies_list
            })
        
        total = total_success + total_fail
        
        return {
            'domain': domain,
            'date': report_date,
            'stats': {
                'total_reports': len(reports),
                'total_providers': len(set(r.organization_name for r in reports)),
                'total_success': total_success,
                'total_fail': total_fail,
                'total_sessions': total,
                'success_rate': round((total_success / total * 100) if total > 0 else 100, 2)
            },
            'providers': providers
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching TLS report details for {domain}/{report_date}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# IMAP SYNC STATUS
# =============================================================================

@router.get("/dmarc/imap/status")
async def get_imap_status(db: Session = Depends(get_db)):
    """
    Get IMAP sync configuration and status
    """
    try:
        # Get latest sync
        latest_sync = db.query(DMARCSync).order_by(
            DMARCSync.started_at.desc()
        ).first()
        
        # Get sync stats (last 24 hours)
        from datetime import datetime, timedelta
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        
        recent_syncs = db.query(DMARCSync).filter(
            DMARCSync.started_at >= twenty_four_hours_ago
        ).all()
        
        total_reports_24h = sum(s.reports_created for s in recent_syncs)
        total_failed_24h = sum(s.reports_failed for s in recent_syncs)
        
        return {
            'enabled': settings.dmarc_imap_enabled,
            'configuration': {
                'host': settings.dmarc_imap_host if settings.dmarc_imap_enabled else None,
                'port': settings.dmarc_imap_port if settings.dmarc_imap_enabled else None,
                'user': settings.dmarc_imap_user if settings.dmarc_imap_enabled else None,
                'folder': settings.dmarc_imap_folder if settings.dmarc_imap_enabled else None,
                'delete_after': settings.dmarc_imap_delete_after if settings.dmarc_imap_enabled else None,
                'interval_seconds': settings.dmarc_imap_interval if settings.dmarc_imap_enabled else None,
                'interval_minutes': round(settings.dmarc_imap_interval / 60, 1) if settings.dmarc_imap_enabled else None
            },
            'latest_sync': {
                'id': latest_sync.id,
                'sync_type': latest_sync.sync_type,
                'started_at': latest_sync.started_at.strftime('%Y-%m-%dT%H:%M:%SZ') if latest_sync.started_at else None,
                'completed_at': latest_sync.completed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if latest_sync.completed_at else None,
                'status': latest_sync.status,
                'emails_found': latest_sync.emails_found,
                'emails_processed': latest_sync.emails_processed,
                'reports_created': latest_sync.reports_created,
                'reports_duplicate': latest_sync.reports_duplicate,
                'reports_failed': latest_sync.reports_failed,
                'error_message': latest_sync.error_message
            } if latest_sync else None,
            'stats_24h': {
                'total_syncs': len(recent_syncs),
                'total_reports_created': total_reports_24h,
                'total_reports_failed': total_failed_24h
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching IMAP status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# MANUAL IMAP SYNC
# =============================================================================

@router.post("/dmarc/imap/sync")
async def trigger_manual_sync(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Manually trigger IMAP sync and update global job status for UI visibility
    """
    if not settings.dmarc_imap_enabled:
        raise HTTPException(
            status_code=400,
            detail="DMARC IMAP sync is not enabled."
        )
    
    try:
        # Cleanup any stuck 'running' status in the specific sync table
        db.query(DMARCSync).filter(DMARCSync.status == 'running').update({
            "status": "failed",
            "error_message": "Interrupted by manual restart"
        })
        db.commit()

        # Update the global job status that the UI monitors
        # This ensures the UI shows "Running" immediately
        update_job_status('dmarc_imap_sync', 'running')
        
        # We define a wrapper function to handle the background task status
        def manual_sync_wrapper():
            try:
                # Perform the actual sync
                result = sync_dmarc_reports_from_imap(sync_type='manual')
                
                if result.get('status') == 'error':
                    update_job_status('dmarc_imap_sync', 'failed', result.get('error_message'))
                else:
                    update_job_status('dmarc_imap_sync', 'success')
            except Exception as e:
                logger.error(f"Manual sync background error: {e}")
                update_job_status('dmarc_imap_sync', 'failed', str(e))

        # Trigger the wrapper in background
        background_tasks.add_task(manual_sync_wrapper)
        
        return {
            'status': 'started',
            'message': 'DMARC IMAP sync started'
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error triggering manual sync: {e}")
        # If triggering fails, mark job as failed
        update_job_status('dmarc_imap_sync', 'failed', str(e))
        raise HTTPException(status_code=500, detail="Internal Server Error")


# =============================================================================
# IMAP SYNC HISTORY
# =============================================================================

@router.get("/dmarc/imap/history")
async def get_sync_history(
    limit: int = 20,
    page: int = 1,
    db: Session = Depends(get_db)
):
    """
    Get history of IMAP sync operations
    """
    try:
        # Get total count
        total = db.query(DMARCSync).count()
        
        # Get paginated results
        offset = (page - 1) * limit
        syncs = db.query(DMARCSync).order_by(
            DMARCSync.started_at.desc()
        ).offset(offset).limit(limit).all()
        
        return {
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit if total > 0 else 0,
            'data': [
                {
                    'id': sync.id,
                    'sync_type': sync.sync_type,
                    'status': sync.status,
                    'started_at': sync.started_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync.started_at else None,
                    'completed_at': sync.completed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync.completed_at else None,
                    'emails_found': sync.emails_found,
                    'emails_processed': sync.emails_processed,
                    'reports_created': sync.reports_created,
                    'reports_duplicate': sync.reports_duplicate,
                    'reports_failed': sync.reports_failed,
                    'error_message': sync.error_message,
                    'failed_emails': sync.failed_emails
                }
                for sync in syncs
            ]
        }
        
    except Exception as e:
        logger.error(f"Error fetching sync history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# UPLOAD
# =============================================================================

@router.post("/dmarc/upload")
async def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Upload and parse DMARC or TLS-RPT report file
    
    Supported formats:
    - DMARC: .xml, .xml.gz, .zip (XML content)
    - TLS-RPT: .json, .json.gz
    """
    if not settings.dmarc_manual_upload_enabled:
        raise HTTPException(
            status_code=403,
            detail="Manual report upload is disabled"
        )

    try:
        file_content = await file.read()
        filename = file.filename.lower()
        
        # Detect file type based on extension
        # TLS-RPT files: .json, .json.gz, .json.zip
        is_tls_rpt = filename.endswith('.json') or filename.endswith('.json.gz') or filename.endswith('.json.zip')
        
        if is_tls_rpt:
            # Process TLS-RPT report
            return await _upload_tls_rpt_report(file_content, file.filename, db)
        else:
            # Process DMARC report (default)
            return await _upload_dmarc_report(file_content, file.filename, db)
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error uploading report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


async def _upload_dmarc_report(file_content: bytes, filename: str, db: Session):
    """Handle DMARC report upload"""
    parsed_data = parse_dmarc_file(file_content, filename)
    
    if not parsed_data:
        raise HTTPException(status_code=400, detail="Failed to parse DMARC report")
    
    records_data = parsed_data.pop('records', [])
    report_data = parsed_data
    
    existing = db.query(DMARCReport).filter(
        DMARCReport.report_id == report_data['report_id']
    ).first()
    
    if existing:
        return {
            'status': 'duplicate',
            'report_type': 'dmarc',
            'message': f'Report {report_data["report_id"]} already exists'
        }
    
    report = DMARCReport(**report_data)
    db.add(report)
    db.flush()
    
    for record_data in records_data:
        record_data['dmarc_report_id'] = report.id
        enriched = enrich_dmarc_record(record_data)
        record = DMARCRecord(**enriched)
        db.add(record)
    
    db.commit()
    
    # Clear cache
    clear_dmarc_cache(db)
    
    return {
        'status': 'success',
        'report_type': 'dmarc',
        'message': f'Uploaded DMARC report for {report.domain} from {report.org_name}',
        'report_id': report.id,
        'records_count': len(records_data)
    }


async def _upload_tls_rpt_report(file_content: bytes, filename: str, db: Session):
    """Handle TLS-RPT report upload"""
    from ..services.tls_rpt_parser import parse_tls_rpt_file
    
    parsed_data = parse_tls_rpt_file(file_content, filename)
    
    if not parsed_data:
        raise HTTPException(status_code=400, detail="Failed to parse TLS-RPT report")
    
    # Extract policies
    policies_data = parsed_data.pop('policies', [])
    
    # Check for duplicate
    existing = db.query(TLSReport).filter(
        TLSReport.report_id == parsed_data['report_id']
    ).first()
    
    if existing:
        return {
            'status': 'duplicate',
            'report_type': 'tls-rpt',
            'message': f'TLS-RPT report {parsed_data["report_id"]} already exists'
        }
    
    # Create TLS report
    tls_report = TLSReport(
        report_id=parsed_data['report_id'],
        organization_name=parsed_data.get('organization_name', 'Unknown'),
        contact_info=parsed_data.get('contact_info', ''),
        policy_domain=parsed_data['policy_domain'],
        start_datetime=parsed_data['start_datetime'],
        end_datetime=parsed_data['end_datetime'],
        raw_json=parsed_data.get('raw_json', '')
    )
    db.add(tls_report)
    db.flush()
    
    # Create policy records
    for policy_data in policies_data:
        policy = TLSReportPolicy(
            tls_report_id=tls_report.id,
            policy_type=policy_data.get('policy_type', 'unknown'),
            policy_domain=policy_data.get('policy_domain', ''),
            policy_string=policy_data.get('policy_string', []),
            mx_host=policy_data.get('mx_host', []),
            successful_session_count=policy_data.get('successful_session_count', 0),
            failed_session_count=policy_data.get('failed_session_count', 0),
            failure_details=policy_data.get('failure_details', [])
        )
        db.add(policy)
    
    db.commit()
    
    # Clear cache
    clear_dmarc_cache(db)
    
    return {
        'status': 'success',
        'report_type': 'tls-rpt',
        'message': f'Uploaded TLS-RPT report for {tls_report.policy_domain} from {tls_report.organization_name}',
        'report_id': tls_report.id,
        'policies_count': len(policies_data)
    }