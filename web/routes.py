"""
Flask Routes for SIGMA Web Interface
"""

from flask import render_template, jsonify, request, send_file
from flask_socketio import emit
import logging
import os
import psutil
from datetime import datetime
import socket
import dns.resolver
import dns.reversename

def init_routes(app, socketio, log_collector, system_monitor, 
                rule_engine, alert_manager, vt_checker, report_gen):
    
    # ==================== MAIN PAGES ====================
    
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/alerts')
    def alerts_page():
        return render_template('alerts.html')
    
    @app.route('/query')
    def query_page():
        return render_template('query.html')
    
    @app.route('/report')
    def report_page():
        return render_template('report.html')
    
    @app.route('/connections')
    def connections_page():
        return render_template('connections.html')
    
    @app.route('/logs')
    def logs_page():
        return render_template('logs.html')
    
    @app.route('/processes')
    def processes_page():
        return render_template('processes.html')
    
    # ==================== API ENDPOINTS ====================
    
    @app.route('/api/system/stats')
    def api_system_stats():
        try:
            stats = system_monitor.get_system_stats()
            # Add CPU per-core data
            if stats and 'cpu' in stats:
                stats['cpu']['percent_per_core'] = psutil.cpu_percent(interval=1, percpu=True)
            return jsonify({'success': True, 'data': stats})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/processes/all')
    def api_processes_all():
        try:
            processes = system_monitor.get_processes()
            clean_processes = []
            for proc in processes:
                clean_proc = {}
                for key, value in proc.items():
                    if value is None:
                        clean_proc[key] = ''
                    elif isinstance(value, (int, float, str, bool)):
                        clean_proc[key] = value
                    else:
                        clean_proc[key] = str(value)
                clean_processes.append(clean_proc)
            return jsonify({'success': True, 'data': clean_processes})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/processes/kill', methods=['POST'])
    def api_processes_kill():
        try:
            data = request.get_json()
            pids = data.get('pids', [])
            if not pids:
                return jsonify({'success': False, 'error': 'No PIDs provided'})
            
            terminated = []
            failed = []
            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    terminated.append(pid)
                except Exception as e:
                    failed.append({'pid': pid, 'error': str(e)})
            
            return jsonify({'success': True, 'terminated': terminated, 'failed': failed})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/connections/all')
    def api_connections_all():
        try:
            connections = system_monitor.get_network_connections()
            for conn in connections:
                conn['threat_level'] = 'LOW'
                remote_port = conn.get('remote_port')
                if remote_port in [4444, 1337, 31337, 5555, 6666, 6667]:
                    conn['threat_level'] = 'HIGH'
                elif remote_port in [8080, 8081, 8888, 9999]:
                    conn['threat_level'] = 'MEDIUM'
            return jsonify({'success': True, 'data': connections})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/alerts')
    def api_alerts():
        try:
            limit = request.args.get('limit', 20, type=int)
            severity = request.args.get('severity', None)
            if severity:
                alerts = alert_manager.get_alerts_by_severity(severity, limit)
            else:
                alerts = alert_manager.get_recent_alerts(limit)
            return jsonify({'success': True, 'data': alerts})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/alerts/stats')
    def api_alerts_stats():
        try:
            stats = alert_manager.get_alert_statistics()
            return jsonify({'success': True, 'data': stats})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/alerts/clear', methods=['POST'])
    def api_alerts_clear():
        try:
            alert_manager.clear_alerts()
            rule_engine.clear_cooldown()
            return jsonify({'success': True, 'message': 'All alerts cleared'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/alerts/export')
    def api_alerts_export():
        try:
            limit = request.args.get('limit', 1000, type=int)
            alerts = alert_manager.get_all_alerts(limit)
            if not alerts:
                return jsonify({'success': False, 'error': 'No alerts to export'}), 404
            return jsonify({'success': True, 'data': alerts})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/connections/export')
    def api_connections_export():
        try:
            connections = system_monitor.get_network_connections()
            if not connections:
                return jsonify({'success': False, 'error': 'No connections to export'}), 404
            for conn in connections:
                remote_port = conn.get('remote_port')
                if remote_port in [4444, 1337, 31337]:
                    conn['threat_level'] = 'HIGH'
                elif remote_port in [5555, 6666, 6667]:
                    conn['threat_level'] = 'MEDIUM'
                else:
                    conn['threat_level'] = 'LOW'
            return jsonify({'success': True, 'data': connections})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/search')
    def api_search():
        try:
            query = request.args.get('q', '')
            if not query:
                return jsonify({'success': False, 'error': 'No query provided'})
            
            query_lower = query.lower()
            results = []
            
            if 'failed login' in query_lower:
                logs = log_collector.get_failed_logins(24)
                results = logs[:50]
            elif 'process creation' in query_lower:
                logs = log_collector.get_process_creation(24)
                results = logs[:50]
            elif 'event' in query_lower:
                import re
                event_match = re.search(r'event\s+(\d+)', query_lower)
                if event_match:
                    event_id = int(event_match.group(1))
                    logs = log_collector.search_logs(event_id=event_id, hours_back=24)
                    results = logs[:50]
            elif 'suspicious process' in query_lower:
                alerts = alert_manager.get_alerts_by_rule('RULE_002', 50)
                results = alerts
            elif 'high severity' in query_lower:
                alerts = alert_manager.get_alerts_by_severity('HIGH', 50)
                results = alerts
            elif 'show alerts' in query_lower:
                alerts = alert_manager.get_recent_alerts(50)
                results = alerts
            else:
                logs = log_collector.search_logs(keyword=query, hours_back=24)
                results = logs[:50]
            
            return jsonify({'success': True, 'data': results, 'query': query})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/logs/search')
    def api_logs_search():
        try:
            log_type = request.args.get('type', None)
            hours = request.args.get('hours', 24, type=int)
            event_id = request.args.get('event_id', None)
            keyword = request.args.get('keyword', None)
            
            if event_id:
                try:
                    event_id = int(event_id)
                except ValueError:
                    event_id = None
            
            # If no log_type specified, get ALL logs (Security, System, Application)
            if not log_type or log_type == 'all':
                all_logs = []
                
                # Get Security logs
                security_logs = log_collector.collect_logs('Security', hours)
                for log in security_logs:
                    log['log_type'] = 'Security'
                all_logs.extend(security_logs)
                
                # Get System logs
                system_logs = log_collector.collect_logs('System', hours)
                for log in system_logs:
                    log['log_type'] = 'System'
                all_logs.extend(system_logs)
                
                # Get Application logs
                app_logs = log_collector.collect_logs('Application', hours)
                for log in app_logs:
                    log['log_type'] = 'Application'
                all_logs.extend(app_logs)
                
                # Apply filters
                filtered = []
                for log in all_logs:
                    matches = True
                    if keyword and keyword.lower() not in log.get('description', '').lower():
                        matches = False
                    if event_id and log.get('event_id') != event_id:
                        matches = False
                    if matches:
                        filtered.append(log)
                
                # Sort by timestamp (most recent first)
                filtered.sort(key=lambda x: x['timestamp'], reverse=True)
                logs = filtered
                
            else:
                # Get specific log type
                logs = log_collector.collect_logs(log_type, hours)
                for log in logs:
                    log['log_type'] = log_type
                
                if keyword or event_id:
                    filtered = []
                    for log in logs:
                        matches = True
                        if keyword and keyword.lower() not in log.get('description', '').lower():
                            matches = False
                        if event_id and log.get('event_id') != event_id:
                            matches = False
                        if matches:
                            filtered.append(log)
                    logs = filtered
            
            return jsonify({'success': True, 'data': logs})
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)})
        
    @app.route('/api/alerts/delete', methods=['POST'])
    def api_alerts_delete():
        """Delete a specific alert"""
        try:
            data = request.get_json()
            alert_id = data.get('id')
            
            if not alert_id:
                return jsonify({'success': False, 'error': 'No alert ID provided'})
            
            success = alert_manager.delete_alert(alert_id)
            
            if success:
                return jsonify({'success': True, 'message': 'Alert deleted'})
            else:
                return jsonify({'success': False, 'error': 'Alert not found'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
        
    @app.route('/api/virustotal/check', methods=['POST'])
    def api_virustotal_check():
        """Check an IP address with VirusTotal"""
        try:
            data = request.get_json()
            ip = data.get('ip', '').strip()
            
            if not ip:
                return jsonify({'success': False, 'error': 'No IP address provided'})
            
            result = vt_checker.check_ip(ip)
            return jsonify(result)
            
        except Exception as e:
            logging.error(f"VirusTotal check error: {str(e)}")
            return jsonify({'success': False, 'error': str(e)})
        
    @app.route('/api/dns/reverse')
    def api_reverse_dns():
        """Get hostname for an IP address using reverse DNS lookup"""
        ip = request.args.get('ip', '')
        if not ip:
            return jsonify({'success': False, 'error': 'No IP provided'})
        
        try:
            # Use dnspython with timeout
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=1.0)
            for rdata in answers:
                hostname = str(rdata).rstrip('.')
                return jsonify({'success': True, 'hostname': hostname})
        except dns.resolver.NXDOMAIN:
            return jsonify({'success': True, 'hostname': None, 'message': 'No PTR record found'})
        except dns.resolver.Timeout:
            return jsonify({'success': False, 'error': 'DNS lookup timeout'})
        except Exception as e:
            # Fallback to socket method
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return jsonify({'success': True, 'hostname': hostname})
            except socket.herror:
                return jsonify({'success': True, 'hostname': None, 'message': 'No reverse DNS record'})
            except Exception as fallback_error:
                return jsonify({'success': False, 'error': str(fallback_error)})
    
    # ==================== REPORT ENDPOINTS ====================
    
    @app.route('/api/report/generate', methods=['POST'])
    def api_generate_report():
        try:
            data = request.get_json() or {}
            hours = data.get('hours', 24)
            
            alerts = alert_manager.get_alerts_by_time(hours, 100)
            stats = system_monitor.get_system_stats()
            connections = system_monitor.get_network_connections()
            
            logs_summary = {}
            for log_type in ['Security', 'System', 'Application']:
                logs = log_collector.collect_logs(log_type, hours)
                logs_summary[log_type] = len(logs)
            
            filename = report_gen.generate_report(
                alerts=alerts,
                system_stats=stats,
                logs_summary=logs_summary,
                connections=connections,
                report_title=f"SIGMA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            filename_only = os.path.basename(filename)
            return jsonify({'success': True, 'file': filename_only})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/report/quick', methods=['POST'])
    def api_quick_report():
        try:
            data = request.get_json() or {}
            hours = data.get('hours', 24)
            
            alerts = alert_manager.get_alerts_by_time(hours, 50)
            stats = system_monitor.get_system_stats()
            connections = system_monitor.get_network_connections()
            
            filename = report_gen.generate_quick_report(
                alerts=alerts,
                system_stats=stats,
                connections=connections
            )
            
            filename_only = os.path.basename(filename)
            return jsonify({'success': True, 'file': filename_only})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/report/download/<filename>')
    def api_download_report(filename):
        try:
            full_path = os.path.join(report_gen.reports_dir, filename)
            if os.path.exists(full_path):
                return send_file(full_path, as_attachment=True, download_name=filename)
            else:
                return jsonify({'success': False, 'error': 'File not found'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/reports/list')
    def api_reports_list():
        reports_dir = report_gen.reports_dir
        files = []
        if os.path.exists(reports_dir):
            for f in os.listdir(reports_dir):
                if f.endswith('.pdf'):
                    filepath = os.path.join(reports_dir, f)
                    stat = os.stat(filepath)
                    files.append({
                        'name': f,
                        'size': stat.st_size,
                        'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
                    })
            files.sort(key=lambda x: x['date'], reverse=True)
        return jsonify({'success': True, 'files': files})
    
    # ==================== SOCKET.IO EVENTS ====================
    
    @socketio.on('request_update')
    def handle_update_request():
        try:
            stats = system_monitor.get_system_stats()
            # Add CPU per-core data for WebSocket
            if stats and 'cpu' in stats:
                stats['cpu']['percent_per_core'] = psutil.cpu_percent(interval=1, percpu=True)
            
            alerts = alert_manager.get_recent_alerts(10)
            conn_stats = system_monitor.get_connection_stats()
            emit('system_update', {
                'stats': stats,
                'alerts': alerts,
                'connections': conn_stats
            })
        except Exception as e:
            emit('system_update', {'error': str(e)})
    
    logging.info("Routes initialized successfully")