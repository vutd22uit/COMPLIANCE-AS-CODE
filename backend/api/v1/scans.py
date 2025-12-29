"""Scan Management API Endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from backend.database.database import get_db
from backend.database.models import User, ScanJob, ScanStatus
from backend.auth.dependencies import get_current_user, get_current_security_engineer
from backend.auth.rbac import Permission, require_permission

router = APIRouter()


# Pydantic models
class ScanCreate(BaseModel):
    environment_id: int
    scan_type: str  # "openstack", "linux", "full"
    scheduled_time: Optional[datetime] = None


class ScanResponse(BaseModel):
    id: int
    environment_id: int
    scan_type: str
    status: str
    scheduled_time: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    result_summary: Optional[dict]
    
    class Config:
        from_attributes = True


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scans for user's organization"""
    require_permission(current_user.role.value, Permission.SCAN_VIEW)
    
    query = db.query(ScanJob).filter(
        ScanJob.organization_id == current_user.organization_id
    )
    
    if status_filter:
        query = query.filter(ScanJob.status == status_filter)
    
    scans = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()
    return scans


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_security_engineer),
    db: Session = Depends(get_db)
):
    """Kích hoạt quét lỗi tự động (chạy ngầm)"""
    require_permission(current_user.role.value, Permission.SCAN_CREATE)
    
    # 1. Lưu bản ghi vào DB
    scan = ScanJob(
        organization_id=current_user.organization_id,
        environment_id=scan_data.environment_id,
        scan_type=scan_data.scan_type,
        status=ScanStatus.PENDING,
        scheduled_time=scan_data.scheduled_time or datetime.utcnow()
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # 2. TỰ ĐỘNG HOÁ: Đẩy vào Celery Worker
    from backend.workers.tasks import run_compliance_scan
    run_compliance_scan.delay(scan_data.scan_type, scan_data.environment_id)
    
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan details"""
    scan = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.organization_id == current_user.organization_id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan
