"""
Terminal Dashboard
Real-time display of IDS alerts and statistics using rich library.
"""

import time
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from collections import Counter


class IDSDashboard:
    """Terminal dashboard for IDS monitoring."""
    
    def __init__(self, detection_engine, packet_capture, refresh_rate=1):
        """
        Initialize dashboard.
        
        Args:
            detection_engine: DetectionEngine instance
            packet_capture: PacketCapture instance
            refresh_rate: Refresh rate in seconds
        """
        self.detection_engine = detection_engine
        self.packet_capture = packet_capture
        self.refresh_rate = refresh_rate
        self.console = Console()
        self.running = False
    
    def _get_severity_color(self, severity):
        """Get color for severity level."""
        colors = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'red',
            'CRITICAL': 'bold red'
        }
        return colors.get(severity, 'white')
    
    def _create_alerts_panel(self):
        """Create alerts feed panel."""
        alerts = self.detection_engine.get_recent_alerts(count=10)
        
        if not alerts:
            return Panel(
                Text("No alerts yet", style="dim"),
                title="[bold]Recent Alerts[/bold]",
                border_style="blue"
            )
        
        alert_text = Text()
        for alert in reversed(alerts[-10:]):  # Show most recent 10
            timestamp = datetime.fromtimestamp(
                alert.get('timestamp', time.time())
            ).strftime('%H:%M:%S')
            
            severity = alert.get('severity', 'UNKNOWN')
            severity_color = self._get_severity_color(severity)
            
            alert_text.append(f"[{timestamp}] ", style="dim")
            alert_text.append(f"[{severity_color}]{severity}[/{severity_color}] ", style="bold")
            alert_text.append(f"{alert.get('rule_name', 'Unknown')} | ", style="cyan")
            alert_text.append(f"{alert.get('src_ip', 'Unknown')}", style="white")
            
            if alert.get('message'):
                alert_text.append(f"\n  └─ {alert.get('message')}", style="dim")
            
            alert_text.append("\n")
        
        return Panel(
            alert_text,
            title="[bold]Recent Alerts[/bold]",
            border_style="blue"
        )
    
    def _create_statistics_panel(self):
        """Create statistics panel."""
        stats = self.detection_engine.get_statistics()
        capture_stats = self.packet_capture.get_statistics()
        
        table = Table(show_header=False, box=None, padding=(0, 1))
        
        # Total alerts
        table.add_row(
            Text("Total Alerts:", style="bold"),
            Text(str(stats['total_alerts']), style="yellow")
        )
        
        # Active rules
        table.add_row(
            Text("Active Rules:", style="bold"),
            Text(str(stats['active_rules']), style="cyan")
        )
        
        # Packets captured
        table.add_row(
            Text("Packets Captured:", style="bold"),
            Text(str(capture_stats['packet_count']), style="green")
        )
        
        # Status
        status = "Running" if capture_stats['running'] else "Stopped"
        status_style = "green" if capture_stats['running'] else "red"
        table.add_row(
            Text("Status:", style="bold"),
            Text(status, style=status_style)
        )
        
        return Panel(
            table,
            title="[bold]Statistics[/bold]",
            border_style="green"
        )
    
    def _create_severity_panel(self):
        """Create severity breakdown panel."""
        stats = self.detection_engine.get_statistics()
        severity_counts = stats.get('severity_counts', {})
        
        table = Table(show_header=False, box=None, padding=(0, 1))
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            color = self._get_severity_color(severity)
            table.add_row(
                Text(severity, style=f"bold {color}"),
                Text(str(count), style=color)
            )
        
        return Panel(
            table,
            title="[bold]Severity Breakdown[/bold]",
            border_style="yellow"
        )
    
    def _create_rules_panel(self):
        """Create rule breakdown panel."""
        stats = self.detection_engine.get_statistics()
        rule_counts = stats.get('rule_counts', {})
        
        if not rule_counts:
            return Panel(
                Text("No rule triggers yet", style="dim"),
                title="[bold]Rule Breakdown[/bold]",
                border_style="magenta"
            )
        
        table = Table(show_header=False, box=None, padding=(0, 1))
        
        # Sort by count (descending)
        sorted_rules = sorted(
            rule_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for rule_name, count in sorted_rules[:5]:  # Top 5
            table.add_row(
                Text(rule_name, style="cyan"),
                Text(str(count), style="white")
            )
        
        return Panel(
            table,
            title="[bold]Rule Breakdown[/bold]",
            border_style="magenta"
        )
    
    def _create_top_sources_panel(self):
        """Create top sources panel."""
        stats = self.detection_engine.get_statistics()
        top_sources = stats.get('top_sources', [])
        
        if not top_sources:
            return Panel(
                Text("No source data yet", style="dim"),
                title="[bold]Top Sources[/bold]",
                border_style="red"
            )
        
        table = Table(show_header=False, box=None, padding=(0, 1))
        
        for src_ip, count in top_sources[:5]:  # Top 5
            table.add_row(
                Text(src_ip, style="red"),
                Text(str(count), style="white")
            )
        
        return Panel(
            table,
            title="[bold]Top Sources[/bold]",
            border_style="red"
        )
    
    def _create_layout(self):
        """Create dashboard layout."""
        layout = Layout()
        
        # Split into header and body
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body")
        )
        
        # Split body into main and sidebar
        layout["body"].split_row(
            Layout(name="main"),
            Layout(name="sidebar", size=40)
        )
        
        # Split main into alerts and stats
        layout["main"].split_column(
            Layout(name="alerts", ratio=2),
            Layout(name="stats", size=8)
        )
        
        # Split sidebar
        layout["sidebar"].split_column(
            Layout(name="severity"),
            Layout(name="rules"),
            Layout(name="sources")
        )
        
        # Fill layout with panels
        layout["header"].update(
            Panel(
                Text("IDS - Intrusion Detection System", style="bold white on blue", justify="center"),
                border_style="blue"
            )
        )
        
        layout["alerts"].update(self._create_alerts_panel())
        layout["stats"].update(self._create_statistics_panel())
        layout["severity"].update(self._create_severity_panel())
        layout["rules"].update(self._create_rules_panel())
        layout["sources"].update(self._create_top_sources_panel())
        
        return layout
    
    def start(self):
        """Start the dashboard."""
        self.running = True
        
        try:
            with Live(self._create_layout(), refresh_per_second=1/self.refresh_rate, screen=True) as live:
                while self.running:
                    live.update(self._create_layout())
                    time.sleep(self.refresh_rate)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the dashboard."""
        self.running = False

