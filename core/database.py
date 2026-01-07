"""
Database Management for NullSpecter Results
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from contextlib import contextmanager
import hashlib

class ScanDatabase:
    """SQLite database for storing scan results"""
    
    def __init__(self, db_path: str = "nullspecter.db"):
        self.db_path = Path(db_path)
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database tables"""
        with self._get_connection() as conn:
            # Scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration REAL,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    risk_level TEXT,
                    config_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Vulnerabilities table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    url TEXT NOT NULL,
                    parameter TEXT,
                    payload TEXT,
                    description TEXT,
                    recommendation TEXT,
                    confidence TEXT,
                    checker_name TEXT,
                    response_code INTEGER,
                    response_length INTEGER,
                    evidence TEXT,
                    hash TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                )
            """)
            
            # Requests table (for debugging)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    response_time REAL,
                    response_length INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                )
            """)
            
            # Checkers table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkers (
                    checker_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    checker_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    execution_time REAL,
                    results_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                )
            """)
            
            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(start_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vulnerability_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_hash ON vulnerabilities(hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checkers_scan ON checkers(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_scan ON requests(scan_id)")
            
            # Statistics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    total_scans INTEGER DEFAULT 0,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    critical_vulns INTEGER DEFAULT 0,
                    high_vulns INTEGER DEFAULT 0,
                    medium_vulns INTEGER DEFAULT 0,
                    low_vulns INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(date)
                )
            """)
    
    def create_scan(self, target_url: str, config: Dict = None) -> str:
        """Create a new scan record"""
        import uuid
        
        scan_id = str(uuid.uuid4())
        config_json = json.dumps(config or {})
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scans (
                    scan_id, target_url, status, start_time, config_json
                ) VALUES (?, ?, ?, ?, ?)
            """, (scan_id, target_url, 'running', datetime.now(), config_json))
        
        return scan_id
    
    def update_scan_status(self, scan_id: str, status: str, 
                          results: Dict = None) -> bool:
        """Update scan status and results"""
        try:
            with self._get_connection() as conn:
                if status == 'completed' and results:
                    conn.execute("""
                        UPDATE scans SET 
                            status = ?,
                            end_time = ?,
                            duration = ?,
                            total_vulnerabilities = ?,
                            critical_count = ?,
                            high_count = ?,
                            medium_count = ?,
                            low_count = ?,
                            risk_level = ?
                        WHERE scan_id = ?
                    """, (
                        status,
                        datetime.now(),
                        results.get('scan_duration'),
                        results.get('total_vulnerabilities', 0),
                        results.get('critical_count', 0),
                        results.get('high_count', 0),
                        results.get('medium_count', 0),
                        results.get('low_count', 0),
                        results.get('risk_level', 'UNKNOWN'),
                        scan_id
                    ))
                else:
                    conn.execute("""
                        UPDATE scans SET status = ? WHERE scan_id = ?
                    """, (status, scan_id))
            return True
        except Exception as e:
            print(f"Error updating scan status: {e}")
            return False
    
    def add_vulnerability(self, scan_id: str, vulnerability: Dict) -> bool:
        """Add a vulnerability to the database"""
        try:
            # Generate hash for duplicate detection
            vuln_data = vulnerability.copy()
            vuln_data.pop('scan_id', None)
            vuln_hash = hashlib.sha256(
                json.dumps(vuln_data, sort_keys=True).encode()
            ).hexdigest()
            
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO vulnerabilities (
                        scan_id, vulnerability_type, severity, url,
                        parameter, payload, description, recommendation,
                        confidence, checker_name, response_code,
                        response_length, evidence, hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    vulnerability.get('type', 'Unknown'),
                    vulnerability.get('severity', 'LOW'),
                    vulnerability.get('url', ''),
                    vulnerability.get('parameter'),
                    vulnerability.get('payload'),
                    vulnerability.get('description'),
                    vulnerability.get('recommendation'),
                    vulnerability.get('confidence', 'MEDIUM'),
                    vulnerability.get('checker'),
                    vulnerability.get('status_code'),
                    vulnerability.get('response_length'),
                    json.dumps(vulnerability.get('evidence', {})),
                    vuln_hash
                ))
            return True
        except Exception as e:
            print(f"Error adding vulnerability: {e}")
            return False
    
    def add_checker_result(self, scan_id: str, checker_name: str, 
                          status: str, results: Dict) -> bool:
        """Add checker execution results"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO checkers (
                        scan_id, checker_name, status, 
                        vulnerabilities_found, execution_time, results_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    checker_name,
                    status,
                    results.get('vulnerabilities_found', 0),
                    results.get('execution_time'),
                    json.dumps(results)
                ))
            return True
        except Exception as e:
            print(f"Error adding checker result: {e}")
            return False
    
    def log_request(self, scan_id: str, method: str, url: str, 
                   status_code: int, response_time: float, 
                   response_length: int) -> bool:
        """Log an HTTP request"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO requests (
                        scan_id, method, url, status_code, 
                        response_time, response_length
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, method, url, status_code, response_time, response_length))
            return True
        except Exception as e:
            print(f"Error logging request: {e}")
            return False
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan details"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM scans WHERE scan_id = ?
                """, (scan_id,))
                
                row = cursor.fetchone()
                if row:
                    result = dict(row)
                    # Parse config JSON
                    if result.get('config_json'):
                        try:
                            result['config'] = json.loads(result['config_json'])
                        except:
                            result['config'] = {}
                    return result
                return None
        except Exception as e:
            print(f"Error getting scan: {e}")
            return None
    
    def get_scan_vulnerabilities(self, scan_id: str) -> List[Dict]:
        """Get all vulnerabilities for a scan"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM vulnerabilities 
                    WHERE scan_id = ? 
                    ORDER BY 
                        CASE severity 
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 4
                            ELSE 5
                        END,
                        vulnerability_type
                """, (scan_id,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting vulnerabilities: {e}")
            return []
    
    def get_recent_scans(self, limit: int = 20, status: str = None) -> List[Dict]:
        """Get recent scans"""
        try:
            with self._get_connection() as conn:
                sql = """
                    SELECT 
                        scan_id, target_url, status, start_time, end_time,
                        duration, total_vulnerabilities, risk_level
                    FROM scans 
                    WHERE 1=1
                """
                params = []
                
                if status:
                    sql += " AND status = ?"
                    params.append(status)
                
                sql += " ORDER BY start_time DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting recent scans: {e}")
            return []
    
    def get_statistics(self, days: int = 30) -> Dict:
        """Get statistics for the last N days"""
        try:
            with self._get_connection() as conn:
                # Overall statistics
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(total_vulnerabilities) as total_vulns,
                        SUM(critical_count) as critical_vulns,
                        SUM(high_count) as high_vulns,
                        SUM(medium_count) as medium_vulns,
                        SUM(low_count) as low_vulns,
                        AVG(duration) as avg_duration
                    FROM scans 
                    WHERE status = 'completed'
                """)
                
                overall = dict(cursor.fetchone() or {})
                
                # Daily statistics
                cursor = conn.execute("""
                    SELECT 
                        DATE(start_time) as date,
                        COUNT(*) as scans,
                        SUM(total_vulnerabilities) as vulnerabilities
                    FROM scans 
                    WHERE status = 'completed' 
                    AND start_time >= DATE('now', ? || ' days')
                    GROUP BY DATE(start_time)
                    ORDER BY date DESC
                """, (f"-{days}",))
                
                daily = [dict(row) for row in cursor.fetchall()]
                
                # Vulnerability type distribution
                cursor = conn.execute("""
                    SELECT 
                        vulnerability_type,
                        COUNT(*) as count,
                        severity
                    FROM vulnerabilities 
                    GROUP BY vulnerability_type, severity
                    ORDER BY count DESC
                    LIMIT 10
                """)
                
                vuln_types = [dict(row) for row in cursor.fetchall()]
                
                # Top vulnerable targets
                cursor = conn.execute("""
                    SELECT 
                        s.target_url,
                        COUNT(v.vuln_id) as vulnerability_count,
                        SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
                    FROM scans s
                    JOIN vulnerabilities v ON s.scan_id = v.scan_id
                    WHERE s.status = 'completed'
                    GROUP BY s.target_url
                    ORDER BY vulnerability_count DESC
                    LIMIT 10
                """)
                
                top_targets = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'overall': overall,
                    'daily': daily,
                    'vulnerability_types': vuln_types,
                    'top_targets': top_targets,
                    'period_days': days
                }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def search_vulnerabilities(self, query: str, 
                              severity: str = None,
                              limit: int = 50) -> List[Dict]:
        """Search vulnerabilities by query"""
        try:
            with self._get_connection() as conn:
                sql = """
                    SELECT v.*, s.target_url, s.start_time
                    FROM vulnerabilities v
                    JOIN scans s ON v.scan_id = s.scan_id
                    WHERE (
                        v.url LIKE ? OR 
                        v.vulnerability_type LIKE ? OR 
                        v.description LIKE ? OR
                        v.payload LIKE ?
                    )
                """
                params = [f"%{query}%"] * 4
                
                if severity:
                    sql += " AND v.severity = ?"
                    params.append(severity)
                
                sql += " ORDER BY v.severity, v.vulnerability_type LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error searching vulnerabilities: {e}")
            return []
    
    def export_scan(self, scan_id: str, format: str = "json") -> Dict:
        """Export complete scan data"""
        try:
            scan = self.get_scan(scan_id)
            if not scan:
                return {}
            
            vulnerabilities = self.get_scan_vulnerabilities(scan_id)
            
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM checkers WHERE scan_id = ?
                """, (scan_id,))
                checkers = [dict(row) for row in cursor.fetchall()]
                
                cursor = conn.execute("""
                    SELECT COUNT(*) as total_requests FROM requests WHERE scan_id = ?
                """, (scan_id,))
                total_requests = cursor.fetchone()['total_requests']
            
            return {
                'scan': scan,
                'vulnerabilities': vulnerabilities,
                'checkers': checkers,
                'statistics': {
                    'total_vulnerabilities': len(vulnerabilities),
                    'total_requests': total_requests,
                    'total_checkers': len(checkers)
                },
                'exported_at': datetime.now().isoformat(),
                'format': format
            }
        except Exception as e:
            print(f"Error exporting scan: {e}")
            return {}
    
    def cleanup_old_scans(self, days_old: int = 30) -> int:
        """Remove scans older than specified days, returns count deleted"""
        try:
            with self._get_connection() as conn:
                # Count before deletion
                cursor = conn.execute("""
                    SELECT COUNT(*) as count FROM scans 
                    WHERE start_time < DATE('now', ? || ' days')
                """, (f"-{days_old}",))
                count_before = cursor.fetchone()['count']
                
                # Delete old scans (cascade will delete related records)
                conn.execute("""
                    DELETE FROM scans 
                    WHERE start_time < DATE('now', ? || ' days')
                """, (f"-{days_old}",))
                
                # Update statistics
                self._update_statistics(conn)
                
                return count_before
        except Exception as e:
            print(f"Error cleaning up old scans: {e}")
            return 0
    
    def _update_statistics(self, conn):
        """Update daily statistics"""
        try:
            conn.execute("""
                INSERT OR REPLACE INTO statistics (
                    date, total_scans, total_vulnerabilities,
                    critical_vulns, high_vulns, medium_vulns, low_vulns
                )
                SELECT 
                    DATE(start_time) as date,
                    COUNT(*) as total_scans,
                    SUM(total_vulnerabilities) as total_vulnerabilities,
                    SUM(critical_count) as critical_vulns,
                    SUM(high_count) as high_vulns,
                    SUM(medium_count) as medium_vulns,
                    SUM(low_count) as low_vulns
                FROM scans 
                WHERE status = 'completed'
                GROUP BY DATE(start_time)
            """)
        except Exception as e:
            print(f"Error updating statistics: {e}")
    
    def backup_database(self, backup_path: str = None) -> str:
        """Create a backup of the database"""
        try:
            if backup_path is None:
                backup_path = f"nullspecter_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            
            import shutil
            shutil.copy2(str(self.db_path), backup_path)
            return backup_path
        except Exception as e:
            print(f"Error backing up database: {e}")
            return ""
    
    def optimize_database(self):
        """Optimize database performance"""
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
                conn.execute("ANALYZE")
                return True
        except Exception as e:
            print(f"Error optimizing database: {e}")
            return False
    
    def get_database_size(self) -> int:
        """Get database file size in bytes"""
        try:
            return self.db_path.stat().st_size
        except:
            return 0


# Global database instance
scan_db = ScanDatabase()