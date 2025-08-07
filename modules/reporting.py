from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from modules.database import get_new_ips_count, get_top_suspicious_ip, get_most_probed_port, get_port_scan_count
import logging
import datetime

# Configure logging
logging.basicConfig(filename='daily_report.log', level=logging.INFO, format='%(message)s')

def generate_daily_report():
    new_ips_count = get_new_ips_count()
    port_scan_count = get_port_scan_count()
    top_suspicious_ip = get_top_suspicious_ip()
    most_probed_port = get_most_probed_port()

    report = (
        f"[Summary] {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
        f"- {new_ips_count} New IPs\n"
        f"- {port_scan_count} Port Scans Detected\n"
        f"- Top IP: {top_suspicious_ip}\n"
        f"- Most Probed Port: {most_probed_port}\n"
    )

    logging.info(report)

# Schedule the daily report generation
scheduler = BlockingScheduler()
trigger = CronTrigger(hour=0, minute=0)  # Run daily at midnight
scheduler.add_job(generate_daily_report, trigger)

if __name__ == "__main__":
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
