"""
Asynchronous Tasks for Compliance Scanning and Remediation
"""

import os
import subprocess
import json
from datetime import datetime
from typing import Optional
import logging

from backend.workers.celery_app import celery_app
from backend.database.database import get_db_context
from backend.database.models import ScanJob, ScanStatus, Finding, FindingStatus, Severity
from evidence.collectors.evidence_collector import EvidenceCollector

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="backend.workers.tasks.run_compliance_scan")
def run_compliance_scan(self, scan_type: str, env_id: int):
    """
    Task tự động chạy InSpec scan và cập nhật kết quả vào DB
    """
    with get_db_context() as db:
        # 1. Tạo bản ghi Job mới
        job = ScanJob(
            organization_id=1,  # Default org
            environment_id=env_id,
            scan_type=scan_type,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow()
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        
        job_id = job.id
        logger.info(f"🚀 Bắt đầu scan tự động [ID: {job_id}] cho {scan_type}")

        try:
            # 2. Xác định đường dẫn profile
            profile_path = "tests/inspec/openstack-cis" if scan_type == "openstack" else "tests/inspec/linux-cis"
            output_file = f"scan-results/automated-{scan_type}-{job_id}.json"
            os.makedirs("scan-results", exist_ok=True)

            # 3. Thực thi InSpec lệnh
            cmd = [
                "inspec", "exec", profile_path,
                "--reporter", f"json:{output_file}",
                "--chef-license", "accept-silent"
            ]
            
            # Chạy subprocess
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # 4. Xử lý kết quả bằng EvidenceCollector (Code cũ của bạn)
            collector = EvidenceCollector()
            raw_evidence = collector.collect_inspec_scan(output_file)
            normalized_findings = collector.normalize_findings(raw_evidence)

            # 5. Lưu findings vào Database
            for f in normalized_findings:
                finding = Finding(
                    finding_id=f['finding_id'],
                    scan_job_id=job_id,
                    control_id=f['control']['id'],
                    control_title=f['control']['title'],
                    severity=Severity(f['severity'].lower()),
                    status=FindingStatus.OPEN if f['status'] == 'FAIL' else FindingStatus.RESOLVED,
                    resource_type=f['resource']['type'],
                    evidence_message=f['evidence']['message']
                )
                db.add(finding)

            # 6. Cập nhật Job hoàn tất
            job.status = ScanStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.result_summary = raw_evidence.get('statistics', {})
            db.commit()
            
            logger.info(f"✅ Scan hoàn tất [ID: {job_id}]. Score: {job.result_summary.get('compliance_score', 0)}%")
            
            # 7. TỰ ĐỘNG HOÁ: Nếu có lỗi Critical, gửi cảnh báo ngay
            if job.result_summary.get('failed_controls', 0) > 0:
                trigger_alerts.delay(job_id)

        except Exception as e:
            logger.error(f"❌ Lỗi khi scan: {str(e)}")
            job.status = ScanStatus.FAILED
            job.error_message = str(e)
            db.commit()

@celery_app.task(name="backend.workers.tasks.trigger_alerts")
def trigger_alerts(job_id: int):
    """
    Tự động gửi thông báo khi phát hiện vi phạm bảo mật
    """
    logger.info(f"🔔 Đang gửi cảnh báo tự động cho Job {job_id}...")
    # TODO: Gọi Slack/Jira API tại đây
    # Ví dụ: requests.post(SLACK_WEBHOOK, json={"text": f"Phát hiện lỗi bảo mật tại Job {job_id}"})
    return True
