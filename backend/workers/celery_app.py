"""
Celery Configuration for Compliance Tasks
"""

import os
from celery import Celery
from celery.schedules import crontab

# Khởi tạo Celery
celery_app = Celery(
    "compliance_tasks",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
)

# Cấu hình
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Ho_Chi_Minh",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max for a scan
)

# Tự động scan các file task trong thư mục tasks
celery_app.autodiscover_tasks(["backend.workers"])

# Cấu hình lịch quét tự động (Scheduler)
celery_app.conf.beat_schedule = {
    "daily-openstack-compliance-scan": {
        "task": "backend.workers.tasks.run_compliance_scan",
        "schedule": crontab(hour=2, minute=0),  # 2:00 AM hàng ngày
        "args": ("openstack", 1)  # (scan_type, env_id)
    },
    "daily-linux-hardening-check": {
        "task": "backend.workers.tasks.run_compliance_scan",
        "schedule": crontab(hour=3, minute=0),  # 3:00 AM hàng ngày
        "args": ("linux", 1)
    },
}
