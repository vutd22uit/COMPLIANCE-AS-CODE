# 🎭 Kịch Bản Demo: "Từ Hỗn Loạn Đến Kiểm Soát"

Kịch bản này được thiết kế để gây ấn tượng mạnh với Ban Lãnh Đạo (C-Level) và các bên liên quan về giá trị doanh nghiệp của hệ thống.

**Thời lượng dự kiến:** 10-15 phút
**Thông điệp chính:** Visibility (Khả năng quan sát) - Agility (Tốc độ phản ứng) - Automation (Tự động hóa).

---

## 🎬 Phần 1: Mở Đầu (The "Hook") - 2 Phút
**Mục tiêu:** Chứng minh sự kiểm soát tuyệt đối.

1.  **Mở Dashboard Grafana** (Full Screen).
    *   *Câu thoại:* "Chào mọi người. Đây là sức khỏe an ninh thời gian thực của toàn bộ hạ tầng OpenStack sản xuất của chúng ta."
    *   *Chỉ vào:* Biểu đồ tròn "Compliance Score" (đang xanh ~95%), biểu đồ xu hướng "Compliance Trend".
    *   *Nhấn mạnh:* "Không phải Excel, không phải báo cáo giấy tháng trước. Đây là **BÂY GIỜ**."

2.  **Chuyển sang Terminal**:
    *   *Hành động:* Gõ `make scan-live` (hoặc giả lập nếu không có env thật).
    *   *Câu thoại:* "Hệ thống tự động quét liên tục. Nhưng điều gì xảy ra khi có sự cố?"

---

## 🔥 Phần 2: Sự Cố (The "Incident") - 3 Phút
**Mục tiêu:** Tạo kịch tính và chứng minh khả năng phát hiện tức thì.

1.  **Giả lập sự cố**:
    *   *Hành động (bí mật/nhanh):* Chạy script `python3 scripts/simulate_incident.py --break`.
    *   *Câu thoại:* "Hãy tưởng tượng một Junior Admin vô tình mở port SSH 22 ra Internet hoặc tắt mã hóa volume lúc 2 giờ sáng."

2.  **Quan sát phản ứng**:
    *   **Trên Dashboard:** Refresh Grafana. Điểm số tụt dốc không phanh (ví dụ: xuống 65%). Các ô màu chuyển sang **ĐỎ**.
    *   *Câu thoại:* "Ngay lập tức, Dashboard phản ánh rủi ro. Chúng ta không cần đợi Audit cuối năm mới biết mình bị hỏng."

3.  **Kiểm tra Alert (Slack/Jira)**:
    *   *Hành động:* Mở Slack (hoặc show terminal output của script notification).
    *   *Câu thoại:* "Hệ thống Alertmanager đã gửi cảnh báo Critical cho đội Security. Một ticket Jira đã được tạo tự động với đầy đủ chi tiết: máy nào, lỗi gì, mức độ nghiêm trọng."

---

## 🛠️ Phần 3: Khắc Phục (The "Fix") - 3 Phút
**Mục tiêu:** Chứng minh sức mạnh của Automation (Tiết kiệm chi phí vận hành).

1.  **Đặt vấn đề**:
    *   *Câu thoại:* "Bình thường, chúng ta mất 2 giờ để họp, 1 giờ để tìm lỗi, và 30 phút để sửa. Tổng cộng gần 4 giờ rủi ro."

2.  **Thực thi Auto-Remediation**:
    *   *Hành động:* Gõ lệnh `make remediate-apply`.
    *   *Output:* Ansible playbook chạy, hiển thị các dòng `changed: [localhost]`.
    *   *Câu thoại:* "Với **Compliance-as-Code**, chúng ta sửa lỗi trong 30 giây. Playbook Ansible tự động đóng port, bật mã hóa, và đưa hệ thống về chuẩn."

3.  **Xác nhận kết quả**:
    *   *Hành động:* Chạy lại `python3 scripts/simulate_incident.py --fix` (để update mock data về xanh).
    *   *Hành động:* Refresh Dashboard.
    *   *Hiệu ứng:* Điểm số leo lại lên 95%+. Màu xanh trở lại.

---

## 📋 Phần 4: Báo Cáo & Kết Luận (The "Proof") - 2 Phút
**Mục tiêu:** Hài lòng Auditor và Quản lý.

1.  **Xuất báo cáo**:
    *   *Hành động:* `make report` và mở file HTML vừa tạo.
    *   *Câu thoại:* "Kiểm toán viên cần bằng chứng? Chúng ta có báo cáo PDF/HTML có thể tạo bất cứ lúc nào, chứa lịch sử chi tiết của cuộc 'khủng hoảng' vừa rồi và cách nó được xử lý."

2.  **Kết luận**:
    *   *Câu thoại:* "Dự án này không chỉ là công cụ. Nó chuyển chúng ta từ thế 'Bị động' sang 'Chủ động', giảm 90% thời gian xử lý sự cố compliance."

---

## 🔧 Chuẩn bị Demo (Trước giờ G)

1.  **Clean up**: `make clean`
2.  **Start Dashboard**: `make dashboard`
3.  **Initial Scan**: `python3 scripts/simulate_incident.py --fix` (đảm bảo dashboard xanh từ đầu).
4.  **Mở sẵn các Tab**: Grafana, Terminal (font chữ to), File Report mẫu.

---
