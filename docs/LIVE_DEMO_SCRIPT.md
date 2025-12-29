# 🎬 KỊCH BẢN DEMO LIVE (TRÊN MÁY THẬT)

Đây là kịch bản dành riêng cho việc demo trên **môi trường thật** (Ubuntu Virtual Machine).

## 🚀 Cách 1: Chạy từ Máy Mac (Nếu SSH Key đã hoạt động)
Dùng khi bạn đã copy được SSH Key thành công.

1.  **Kết nối vào máy Ubuntu:**
    ```bash
    ssh eployer10@172.20.10.13  # (Hoặc IP nào bạn đang thấy đúng)
    ```

2.  **Khởi tạo Biến môi trường:**
    ```bash
    export OPENSTACK_HOST="172.20.10.13"
    export OPENSTACK_USER="eployer10"
    ```

3.  **Chạy Quét (Scan):**
    ```bash
    make scan-live
    ```

---

## 🛡️ Cách 2: Chạy TRỰC TIẾP trên Terrminal Ubuntu (Nếu SSH Key bị lỗi)
**Đây là cách chắc chắn thành công 100% nếu bạn đang ngồi trước màn hình máy ảo.**

1.  **Mở Terminal ngay trên Ubuntu.**
2.  **Clone code về (nếu chưa có):**
    ```bash
    git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
    cd COMPLIANCE-AS-CODE
    ```
3.  **Cài đặt (chạy 1 lần):**
    ```bash
    make install
    ```
4.  **Chạy Quét (Scan) trên chính máy này:**
    Mở file `Makefile`, tìm dòng `scan-live` và sửa đoạn ssh target thành `local://`:
    ```makefile
    # Sửa file Makefile:
    # Thay dòng: -t ssh://$(OPENSTACK_USER)@$(OPENSTACK_HOST)
    # Thành:     -t local://
    ```
    
    Hoặc chạy lệnh thủ công:
    ```bash
    inspec exec tests/inspec/openstack-cis \
      -t local:// \
      --reporter cli html:report.html
    ```

5.  **Xem kết quả:**
    Mở file `report.html` vừa sinh ra bằng Firefox trên Ubuntu để xem báo cáo đẹp lung linh.

---

## 🎥 Kịch bản nói khi Demo (Lời thoại)

**Người demo:** "Thưa các anh chị, đây không phải là mô phỏng. Đây là tôi đang quét trực tiếp trên hệ thống OpenStack đang chạy."

*(Gõ lệnh `make scan-live`)*

**Người demo:** "Hệ thống đang kiểm tra 78 cấu hình bảo mật của Keystone, Nova, và Neutron..."

*(Chờ màn hình hiện kết quả ĐỎ/XANH)*

**Người demo:** "Như mọi người thấy, phát hiện ngay lập tức lỗi `PermitRootLogin` đang để là `yes`. Bây giờ tôi sẽ fix nó."

*(Gõ lệnh `make remediate-apply`)*

**Người demo:** "Đã sửa xong. Tôi quét lại lần nữa để chứng minh."

*(Gõ lại `make scan-live` -> Kết quả XANH)*

**Người demo:** "Hệ thống đã an toàn. Xin cảm ơn!"
